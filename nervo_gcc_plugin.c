/*
 * nervo_gcc_plugin.c — GCC plugin for Nervo (Linux Kernel GPS)
 *
 * Tracks every place in C where a function pointer is assigned or a call
 * is made.  Covers all six categories:
 *
 *  FUNCTION POINTER ASSIGNMENTS
 *   1. Static struct initializer   static struct proto_ops x = { .fn = foo }
 *   2. Static array initializer    static fn_t tbl[N] = { [2] = foo }
 *   3. Runtime struct field        ops->create = inet_create
 *   4. Runtime array slot          net_families[AF_INET] = &ops
 *   5. Local variable              fn_t cb = &foo
 *   6. Argument-passed             register(&ops)  where ops.fn = foo
 *
 *  CALLS
 *   7. Direct calls                inet_create(net, sock, ...)
 *   8. Indirect calls              ops->sendmsg(sk, msg, ...)   (call site captured)
 *
 *  BRANCHES
 *   9. if / else (GIMPLE_COND)     if (family == AF_INET)
 *  10. switch / case               switch (sock->type)
 *
 * Output per TU:
 *   $NERVO_OUT/<mangled>.json          — all records for this TU
 *   $NERVO_OUT/nervo_compiled_files.txt — manifest of compiled files
 *
 * Record types emitted:
 *   CallEdge          { callerFn, calleeFn, file, line }
 *   IndirectCall      { callerFn, callExpr, file, line, argCount }
 *   FnPtrAssignment   { structType, fieldName, targetFn, sourceFile, line,
 *                       arrayIndex, context }
 *   BranchCondition   { function, conditionOp, conditionLHS, conditionRHSLabel,
 *                       conditionRHSValue, lhsArgPos }
 *
 * Build:
 *   make -f nervo_plugin.mk
 */

#include "gcc-plugin.h"
#include "plugin-version.h"
#include "tree.h"
#include "tree-pass.h"
#include "gimple.h"
#include "gimple-iterator.h"
#include "gimple-walk.h"
#include "cgraph.h"
#include "context.h"
#include "function.h"
#include "basic-block.h"
#include "cfg.h"
#include "cfghooks.h"
#include "diagnostic.h"
#include "stringpool.h"
#include "attribs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>

int plugin_is_GPL_compatible;

/* ── configuration ─────────────────────────────────────────────────────────── */
#define NERVO_OUT_DEFAULT "/tmp/nervo_out"
static char nervo_out_dir[4096]       = NERVO_OUT_DEFAULT;
static char compiled_files_path[4096];

static pthread_mutex_t manifest_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ═══════════════════════════════════════════════════════════════════════════
 * JSON helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} jbuf_t;

static void jbuf_init(jbuf_t *j) {
    j->cap = 4096;
    j->len = 0;
    j->buf = (char *)xmalloc(j->cap);
    j->buf[0] = '\0';
}

static void jbuf_free(jbuf_t *j) { free(j->buf); }

static void jbuf_grow(jbuf_t *j, size_t need) {
    while (j->len + need + 1 > j->cap) {
        j->cap *= 2;
        j->buf  = (char *)xrealloc(j->buf, j->cap);
    }
}

static void jbuf_append(jbuf_t *j, const char *s) {
    size_t n = strlen(s);
    jbuf_grow(j, n);
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = '\0';
}

static void jbuf_str(jbuf_t *j, const char *s) {
    if (!s) { jbuf_append(j, "null"); return; }
    jbuf_append(j, "\"");
    for (const char *p = s; *p; p++) {
        char esc[4];
        switch (*p) {
            case '"':  jbuf_append(j, "\\\""); break;
            case '\\': jbuf_append(j, "\\\\"); break;
            case '\n': jbuf_append(j, "\\n");  break;
            case '\r': jbuf_append(j, "\\r");  break;
            case '\t': jbuf_append(j, "\\t");  break;
            default:   esc[0] = *p; esc[1] = '\0'; jbuf_append(j, esc);
        }
    }
    jbuf_append(j, "\"");
}

static void jbuf_kv_str(jbuf_t *j, const char *k, const char *v, int comma) {
    jbuf_append(j, "\""); jbuf_append(j, k); jbuf_append(j, "\": ");
    jbuf_str(j, v);
    if (comma) jbuf_append(j, ", ");
}

static void jbuf_kv_int(jbuf_t *j, const char *k, long long v, int comma) {
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "\"%s\": %lld", k, v);
    jbuf_append(j, tmp);
    if (comma) j1buf_append(j, ", ");
}

static void jbuf_kv_null(jbuf_t *j, const char *k, int comma) {
    jbuf_append(j, "\""); jbuf_append(j, k); jbuf_append(j, "\": null");
    if (comma) jbuf_append(j, ", ");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Tree helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char *fn_name(tree decl) {
    if (!decl || TREE_CODE(decl) != FUNCTION_DECL) return NULL;
    tree id = DECL_NAME(decl);
    return id ? IDENTIFIER_POINTER(id) : NULL;
}

static const char *stmt_file(gimple *stmt) {
    location_t loc = gimple_location(stmt);
    return (loc == UNKNOWN_LOCATION) ? NULL : LOCATION_FILE(loc);
}

static int stmt_line(gimple *stmt) {
    location_t loc = gimple_location(stmt);
    return (loc == UNKNOWN_LOCATION) ? -1 : LOCATION_LINE(loc);
}

static int try_get_int(tree t, long long *out) {
    if (!t) return 0;
    STRIP_NOPS(t);
    if (TREE_CODE(t) == INTEGER_CST) {
        *out = (long long)TREE_INT_CST_LOW(t);
        return 1;
    }
    if (TREE_CODE(t) == VAR_DECL && DECL_INITIAL(t)) {
        tree init = DECL_INITIAL(t);
        STRIP_NOPS(init);
        if (TREE_CODE(init) == INTEGER_CST) {
            *out = (long long)TREE_INT_CST_LOW(init);
            return 1;
        }
    }
    return 0;
}

static const char *const_label(tree t) {
    if (!t) return NULL;
    STRIP_NOPS(t);
    if (TREE_CODE(t) == VAR_DECL || TREE_CODE(t) == CONST_DECL) {
        tree id = DECL_NAME(t);
        if (id) return IDENTIFIER_POINTER(id);
    }
    return NULL;
}

/* get the struct type name from a tree type node */
static const char *struct_type_name(tree type_node) {
    if (!type_node) return NULL;
    STRIP_NOPS(type_node);
    if (TREE_CODE(type_node) == POINTER_TYPE)
        type_node = TREE_TYPE(type_node);
    if (!type_node) return NULL;
    tree tn = TYPE_NAME(type_node);
    if (!tn) return NULL;
    if (TREE_CODE(tn) == TYPE_DECL && DECL_NAME(tn))
        return IDENTIFIER_POINTER(DECL_NAME(tn));
    if (TREE_CODE(tn) == IDENTIFIER_NODE)
        return IDENTIFIER_POINTER(tn);
    return NULL;
}

/* resolve the function decl from any fn-pointer-like tree */
static tree resolve_fn_decl(tree t) {
    if (!t) return NULL_TREE;
    STRIP_NOPS(t);
    if (TREE_CODE(t) == ADDR_EXPR) {
        tree inner = TREE_OPERAND(t, 0);
        if (inner && TREE_CODE(inner) == FUNCTION_DECL)
            return inner;
    }
    if (TREE_CODE(t) == FUNCTION_DECL)
        return t;
    return NULL_TREE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Per-TU accumulator
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    jbuf_t records;
    int    count;
} tu_data_t;

static tu_data_t *current_tu = NULL;

static void tu_record(tu_data_t *td, const char *json_obj) {
    if (td->count > 0) jbuf_append(&td->records, ",\n");
    jbuf_append(&td->records, json_obj);
    td->count++;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Emitters
 * ═══════════════════════════════════════════════════════════════════════════ */

static void emit_call_edge(tu_data_t *td, const char *caller,
                           const char *callee, const char *file, int line) {
    jbuf_t j; jbuf_init(&j);
    jbuf_append(&j, "{ ");
    jbuf_kv_str(&j, "type",     "CallEdge", 1);
    jbuf_kv_str(&j, "callerFn", caller,     1);
    jbuf_kv_str(&j, "calleeFn", callee,     1);
    jbuf_kv_str(&j, "file",     file,       1);
    jbuf_kv_int(&j, "line",     line,       0);
    jbuf_append(&j, " }");
    tu_record(td, j.buf);
    jbuf_free(&j);
}

static void emit_indirect_call(tu_data_t *td, const char *caller,
                               const char *call_expr, const char *file,
                               int line, int arg_count) {
    jbuf_t j; jbuf_init(&j);
    jbuf_append(&j, "{ ");
    jbuf_kv_str(&j, "type",      "IndirectCall", 1);
    jbuf_kv_str(&j, "callerFn",  caller,         1);
    jbuf_kv_str(&j, "callExpr",  call_expr,       1);
    jbuf_kv_str(&j, "file",      file,            1);
    jbuf_kv_int(&j, "line",      line,            1);
    jbuf_kv_int(&j, "argCount",  arg_count,       0);
    jbuf_append(&j, " }");
    tu_record(td, j.buf);
    jbuf_free(&j);
}

static void emit_fn_ptr_assign(tu_data_t *td,
                               const char *struct_type, const char *field_name,
                               const char *target_fn,   const char *source_file,
                               int line, int has_index, long long array_index,
                               const char *context) {
    jbuf_t j; jbuf_init(&j);
    jbuf_append(&j, "{ ");
    jbuf_kv_str(&j, "type",       "FnPtrAssignment", 1);
    jbuf_kv_str(&j, "structType", struct_type,        1);
    jbuf_kv_str(&j, "fieldName",  field_name,         1);
    jbuf_kv_str(&j, "targetFn",   target_fn,          1);
    jbuf_kv_str(&j, "sourceFile", source_file,        1);
    jbuf_kv_int(&j, "line",       line,               1);
    jbuf_kv_str(&j, "context",    context,            1);
    if (has_index)
        jbuf_kv_int(&j, "arrayIndex", array_index, 0);
    else
        jbuf_kv_null(&j, "arrayIndex", 0);
    jbuf_append(&j, " }");
    tu_record(td, j.buf);
    jbuf_free(&j);
}

static void emit_branch(tu_data_t *td, const char *function,
                        const char *cond_op, const char *lhs,
                        const char *rhs_label, long long rhs_value,
                        int lhs_arg_pos) {
    jbuf_t j; jbuf_init(&j);
    jbuf_append(&j, "{ ");
    jbuf_kv_str(&j, "type",             "BranchCondition", 1);
    jbuf_kv_str(&j, "function",         function,           1);
    jbuf_kv_str(&j, "conditionOp",      cond_op,            1);
    jbuf_kv_str(&j, "conditionLHS",     lhs,                1);
    jbuf_kv_str(&j, "conditionRHSLabel",rhs_label,          1);
    jbuf_kv_int(&j, "conditionRHSValue",rhs_value,          1);
    jbuf_kv_int(&j, "lhsArgPos",        lhs_arg_pos,        0);
    jbuf_append(&j, " }");
    tu_record(td, j.buf);
    jbuf_free(&j);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CATEGORY 1 + 2: Static struct/array initializers (DECL_INITIAL walker)
 *
 * Walks the CONSTRUCTOR tree of every global variable declaration.
 * This captures:
 *   static struct net_proto_family inet_family_ops = { .create = inet_create }
 *   static struct proto tcp_prot = { .sendmsg = tcp_sendmsg, ... }
 *   static fn_t net_families[NPROTO] = { [AF_INET] = &inet_family_ops }
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Recursively walk a CONSTRUCTOR tree.
 *
 * parent_type:   struct type name of the enclosing struct (NULL for arrays)
 * array_name:    variable name if the top-level container is an array
 * base_index:    array index of this CONSTRUCTOR element (-1 if not in array)
 * src_file:      source file of the declaration
 * line:          source line of the declaration
 * depth:         recursion depth guard
 */
static void walk_constructor(tu_data_t *td, tree ctor,
                             const char *parent_type,
                             const char *array_name,
                             long long   base_index,
                             int         has_base_index,
                             const char *src_file,
                             int         line,
                             int         depth) {
    if (!ctor || TREE_CODE(ctor) != CONSTRUCTOR || depth > 8)
        return;

    unsigned int i;
    tree field_idx, value;

    FOR_EACH_CONSTRUCTOR_ELT(CONSTRUCTOR_ELTS(ctor), i, field_idx, value) {
        if (!value) continue;
        STRIP_NOPS(value);

        /* ── case A: value is a function pointer ──────────────────────── */
        tree fn_decl = resolve_fn_decl(value);
        if (fn_decl) {
            const char *target = fn_name(fn_decl);
            if (!target) continue;

            if (field_idx && TREE_CODE(field_idx) == FIELD_DECL) {
                /* struct field: { .sendmsg = tcp_sendmsg } */
                const char *field_str = NULL;
                if (DECL_NAME(field_idx))
                    field_str = IDENTIFIER_POINTER(DECL_NAME(field_idx));

                emit_fn_ptr_assign(td, parent_type, field_str, target,
                                   src_file, line, has_base_index,
                                   base_index, "static_init");

            } else if (field_idx && TREE_CODE(field_idx) == INTEGER_CST) {
                /* array slot: { [AF_INET] = &inet_create } */
                long long idx = (long long)TREE_INT_CST_LOW(field_idx);
                emit_fn_ptr_assign(td, NULL, array_name ? array_name : "[]",
                                   target, src_file, line, 1, idx,
                                   "static_array_init");

            } else {
                /* positional: no explicit index */
                emit_fn_ptr_assign(td, parent_type,
                                   array_name ? array_name : "[]",
                                   target, src_file, line,
                                   has_base_index, base_index,
                                   "static_init");
            }
            continue;
        }

        /* ── case B: value is a nested CONSTRUCTOR (nested struct/array) ── */
        if (TREE_CODE(value) == CONSTRUCTOR) {
            const char *nested_type = NULL;
            long long   nested_idx  = -1;
            int         nested_has_idx = 0;

            if (field_idx && TREE_CODE(field_idx) == FIELD_DECL) {
                /* struct field containing a sub-struct */
                nested_type = struct_type_name(TREE_TYPE(value));
                if (!nested_type && DECL_NAME(field_idx))
                    nested_type = IDENTIFIER_POINTER(DECL_NAME(field_idx));
            } else if (field_idx && TREE_CODE(field_idx) == INTEGER_CST) {
                /* array element that is itself a struct */
                nested_idx     = (long long)TREE_INT_CST_LOW(field_idx);
                nested_has_idx = 1;
                nested_type    = struct_type_name(TREE_TYPE(value));
            }

            walk_constructor(td, value,
                             nested_type ? nested_type : parent_type,
                             array_name,
                             nested_has_idx ? nested_idx : base_index,
                             nested_has_idx ? 1 : has_base_index,
                             src_file, line, depth + 1);
            continue;
        }

        /* ── case C: value is ADDR_EXPR of a VAR_DECL (struct passed by ptr) */
        if (TREE_CODE(value) == ADDR_EXPR) {
            tree inner = TREE_OPERAND(value, 0);
            if (inner && TREE_CODE(inner) == VAR_DECL
                      && DECL_INITIAL(inner)
                      && TREE_CODE(DECL_INITIAL(inner)) == CONSTRUCTOR) {
                const char *inner_type = struct_type_name(TREE_TYPE(inner));
                walk_constructor(td, DECL_INITIAL(inner),
                                 inner_type, NULL, -1, 0,
                                 src_file, line, depth + 1);
            }
        }
    }
}

/*
 * Called once per TU after all functions have been compiled.
 * Walks every global variable in the varpool for this TU and
 * processes its DECL_INITIAL if it is a CONSTRUCTOR.
 */
static void walk_globals(tu_data_t *td) {
    varpool_node *vnode;

    FOR_EACH_VARIABLE(vnode) {
        tree decl = vnode->decl;
        if (!decl || TREE_CODE(decl) != VAR_DECL) continue;

        tree init = DECL_INITIAL(decl);
        if (!init || TREE_CODE(init) != CONSTRUCTOR) continue;

        /* only process variables defined in this TU */
        const char *src = DECL_SOURCE_FILE(decl);
        if (!src) src = main_input_filename;
        if (!src) continue;

        int  line      = DECL_SOURCE_LINE(decl);
        const char *stype = struct_type_name(TREE_TYPE(decl));

        /* array variable: net_families[NPROTO] */
        const char *arr_name = NULL;
        if (TREE_CODE(TREE_TYPE(decl)) == ARRAY_TYPE) {
            if (DECL_NAME(decl))
                arr_name = IDENTIFIER_POINTER(DECL_NAME(decl));
        }

        walk_constructor(td, init, stype, arr_name, -1, 0, src, line, 0);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CATEGORY 3 + 4 + 5: Runtime GIMPLE assignments
 *
 * Handles:
 *   ops->create = inet_create        (COMPONENT_REF on pointer)
 *   net_families[AF_INET] = &ops     (ARRAY_REF of VAR_DECL)
 *   fn_t cb = &foo                   (local VAR_DECL)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void handle_assign(tu_data_t *td, gassign *stmt,
                          const char *src_file, int line) {
    tree lhs = gimple_assign_lhs(stmt);
    tree rhs = gimple_assign_rhs1(stmt);
    if (!lhs || !rhs) return;

    /* rhs must be a function pointer */
    tree fn_decl = resolve_fn_decl(rhs);
    if (!fn_decl) return;
    const char *target = fn_name(fn_decl);
    if (!target) return;

    long long array_index = 0;
    int       has_index   = 0;
    tree      comp        = lhs;

    /* strip array indexing layer */
    if (TREE_CODE(lhs) == ARRAY_REF) {
        tree idx = TREE_OPERAND(lhs, 1);
        if (try_get_int(idx, &array_index))
            has_index = 1;
        comp = TREE_OPERAND(lhs, 0);
    }

    if (TREE_CODE(comp) == COMPONENT_REF) {
        /* struct field assignment: ops->sendmsg = tcp_sendmsg */
        tree obj   = TREE_OPERAND(comp, 0);
        tree field = TREE_OPERAND(comp, 1);
        if (!obj || !field || TREE_CODE(field) != FIELD_DECL) return;

        const char *stype      = struct_type_name(TREE_TYPE(obj));
        const char *field_str  = NULL;
        if (DECL_NAME(field))
            field_str = IDENTIFIER_POINTER(DECL_NAME(field));

        emit_fn_ptr_assign(td, stype, field_str, target,
                           src_file, line, has_index, array_index,
                           "runtime_struct");

    } else if (TREE_CODE(comp) == VAR_DECL && has_index) {
        /* array slot: net_families[2] = &inet_ops */
        const char *arr_name = NULL;
        if (DECL_NAME(comp))
            arr_name = IDENTIFIER_POINTER(DECL_NAME(comp));
        emit_fn_ptr_assign(td, arr_name, "[]", target,
                           src_file, line, 1, array_index,
                           "runtime_array");

    } else if (TREE_CODE(comp) == VAR_DECL) {
        /* local / global variable: fn_t cb = &foo */
        /* only emit if the type looks like a function pointer */
        tree vtype = TREE_TYPE(comp);
        if (TREE_CODE(vtype) == POINTER_TYPE &&
            TREE_CODE(TREE_TYPE(vtype)) == FUNCTION_TYPE) {
            const char *var_name = NULL;
            if (DECL_NAME(comp))
                var_name = IDENTIFIER_POINTER(DECL_NAME(comp));
            emit_fn_ptr_assign(td, NULL, var_name, target,
                               src_file, line, 0, 0,
                               "local_var");
        }

    } else if (TREE_CODE(comp) == MEM_REF || TREE_CODE(comp) == INDIRECT_REF) {
        /* *ptr = &fn  — anonymous pointer write */
        emit_fn_ptr_assign(td, NULL, "*ptr", target,
                           src_file, line, 0, 0,
                           "ptr_write");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CATEGORY 6 + 7 + 8: Calls (direct, indirect, argument-passed fn ptrs)
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Build a printable string describing an indirect call's fn expression.
 * We try to reconstruct something like "ops->sendmsg" from the tree.
 * Falls back to a generic label if we can't.
 */
static void describe_indirect(tree fn, char *out, size_t outlen) {
    STRIP_NOPS(fn);
    if (TREE_CODE(fn) == MEM_REF || TREE_CODE(fn) == INDIRECT_REF) {
        tree inner = TREE_OPERAND(fn, 0);
        if (inner && TREE_CODE(inner) == SSA_NAME) {
            tree var = SSA_NAME_VAR(inner);
            if (var && DECL_NAME(var)) {
                snprintf(out, outlen, "(*%s)()",
                         IDENTIFIER_POINTER(DECL_NAME(var)));
                return;
            }
        }
    }
    if (TREE_CODE(fn) == COMPONENT_REF) {
        tree obj   = TREE_OPERAND(fn, 0);
        tree field = TREE_OPERAND(fn, 1);
        const char *obj_name   = NULL;
        const char *field_name = NULL;
        if (obj && TREE_CODE(obj) == SSA_NAME) {
            tree var = SSA_NAME_VAR(obj);
            if (var && DECL_NAME(var))
                obj_name = IDENTIFIER_POINTER(DECL_NAME(var));
        }
        if (field && TREE_CODE(field) == FIELD_DECL && DECL_NAME(field))
            field_name = IDENTIFIER_POINTER(DECL_NAME(field));
        if (obj_name && field_name)
            snprintf(out, outlen, "%s->%s()", obj_name, field_name);
        else if (field_name)
            snprintf(out, outlen, "->%s()", field_name);
        else
            snprintf(out, outlen, "<indirect_call>");
        return;
    }
    snprintf(out, outlen, "<indirect_call>");
}

static void handle_call(tu_data_t *td, gcall *stmt,
                        const char *caller, const char *src_file, int line) {
    tree fn = gimple_call_fn(stmt);
    if (!fn) return;
    STRIP_NOPS(fn);

    /* ── direct call ──────────────────────────────────────────────────── */
    const char *callee = NULL;
    if (TREE_CODE(fn) == ADDR_EXPR) {
        tree decl = TREE_OPERAND(fn, 0);
        if (decl && TREE_CODE(decl) == FUNCTION_DECL)
            callee = fn_name(decl);
    } else if (TREE_CODE(fn) == FUNCTION_DECL) {
        callee = fn_name(fn);
    }

    if (callee) {
        emit_call_edge(td, caller, callee, src_file, line);
    } else {
        /* ── indirect call — emit call site record ───────────────────── */
        char expr[256];
        describe_indirect(fn, expr, sizeof(expr));
        int argc = gimple_call_num_args(stmt);
        emit_indirect_call(td, caller, expr, src_file, line, argc);
    }

    /* ── CATEGORY 6: scan arguments for fn-ptr passing ───────────────── */
    /*
     * register_netdevice(dev) where dev->netdev_ops = &igb_netdev_ops
     * is already caught by the struct init walker, but sometimes code does:
     *   sock_register(&inet_family_ops)
     * where inet_family_ops is a local variable whose address is taken.
     * We capture the ADDR_EXPR arguments as "passed to call" records.
     */
    unsigned int nargs = gimple_call_num_args(stmt);
    for (unsigned int i = 0; i < nargs; i++) {
        tree arg = gimple_call_arg(stmt, i);
        if (!arg) continue;
        STRIP_NOPS(arg);

        /* direct fn ptr passed as arg: register_handler(my_callback) */
        tree fn_decl2 = resolve_fn_decl(arg);
        if (fn_decl2) {
            const char *target = fn_name(fn_decl2);
            if (target) {
                char arg_label[64];
                snprintf(arg_label, sizeof(arg_label), "arg%u", i);
                emit_fn_ptr_assign(td, NULL, arg_label, target,
                                   src_file, line, 0, 0,
                                   callee ? "arg_to_call" : "arg_to_indirect");
            }
            continue;
        }

        /* address of a struct variable passed as arg */
        if (TREE_CODE(arg) == ADDR_EXPR) {
            tree inner = TREE_OPERAND(arg, 0);
            if (inner && TREE_CODE(inner) == VAR_DECL
                      && DECL_INITIAL(inner)
                      && TREE_CODE(DECL_INITIAL(inner)) == CONSTRUCTOR) {
                const char *stype = struct_type_name(TREE_TYPE(inner));
                walk_constructor(td, DECL_INITIAL(inner),
                                 stype, NULL, -1, 0,
                                 src_file, line, 0);
            }
        }
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * SSA definition tracker
 *
 * The kernel uses struct field accesses as branch conditions:
 *   if (sock->type == SOCK_STREAM)
 *
 * After SSA construction this becomes:
 *   _1 = sock->type;          // GIMPLE_ASSIGN
 *   if (_1 == 1) goto ...     // GIMPLE_COND
 *
 * The GIMPLE_COND sees anonymous _1 with no name. We fix this by doing a
 * first pass over each basic block to build a map:
 *   SSA version number → (field_name, var_name, arg_pos)
 *
 * Then handle_cond looks up the SSA name in this map to recover the
 * original variable or field name.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define SSA_MAP_SIZE 4096

typedef struct {
    unsigned int ssa_ver;
    char         name[128];   /* field name or variable name */
    int          arg_pos;     /* -1 if not a function parameter */
} ssa_entry_t;

typedef struct {
    ssa_entry_t entries[SSA_MAP_SIZE];
    int         count;
} ssa_map_t;

static void ssa_map_clear(ssa_map_t *m) { m->count = 0; }

static void ssa_map_put(ssa_map_t *m, unsigned int ver,
                        const char *name, int arg_pos) {
    if (!name || m->count >= SSA_MAP_SIZE) return;
    /* overwrite if already exists */
    for (int i = 0; i < m->count; i++) {
        if (m->entries[i].ssa_ver == ver) {
            strncpy(m->entries[i].name, name, sizeof(m->entries[i].name) - 1);
            m->entries[i].arg_pos = arg_pos;
            return;
        }
    }
    m->entries[m->count].ssa_ver = ver;
    strncpy(m->entries[m->count].name, name, sizeof(m->entries[m->count].name) - 1);
    m->entries[m->count].name[sizeof(m->entries[m->count].name) - 1] = '';
    m->entries[m->count].arg_pos = arg_pos;
    m->count++;
}

static const ssa_entry_t *ssa_map_get(const ssa_map_t *m, unsigned int ver) {
    for (int i = 0; i < m->count; i++)
        if (m->entries[i].ssa_ver == ver) return &m->entries[i];
    return NULL;
}

/* per-function SSA map — rebuilt for each function */
static ssa_map_t g_ssa_map;

/*
 * First pass over a basic block: record all GIMPLE_ASSIGN statements of the
 * form:  ssa_name = struct_field   or   ssa_name = param
 * so that handle_cond can look up anonymous SSA names.
 */
static void build_ssa_map_bb(basic_block bb) {
    for (gimple_stmt_iterator gsi = gsi_start_bb(bb);
         !gsi_end_p(gsi); gsi_next(&gsi)) {
        gimple *stmt = gsi_stmt(gsi);
        if (gimple_code(stmt) != GIMPLE_ASSIGN) continue;

        tree lhs = gimple_assign_lhs(stmt);
        tree rhs = gimple_assign_rhs1(stmt);
        if (!lhs || !rhs) continue;
        if (TREE_CODE(lhs) != SSA_NAME) continue;

        unsigned int ver = SSA_NAME_VERSION(lhs);
        STRIP_NOPS(rhs);

        /* case A: ssa = struct_field  (e.g. _1 = sock->type) */
        if (TREE_CODE(rhs) == COMPONENT_REF) {
            tree field = TREE_OPERAND(rhs, 1);
            if (field && TREE_CODE(field) == FIELD_DECL && DECL_NAME(field)) {
                ssa_map_put(&g_ssa_map,
                            ver,
                            IDENTIFIER_POINTER(DECL_NAME(field)),
                            -1);
            }
            continue;
        }

        /* case B: ssa = param  (direct copy of a function argument) */
        if (TREE_CODE(rhs) == PARM_DECL) {
            int pos = arg_pos_of(rhs);
            if (DECL_NAME(rhs))
                ssa_map_put(&g_ssa_map,
                            ver,
                            IDENTIFIER_POINTER(DECL_NAME(rhs)),
                            pos);
            continue;
        }

        /* case C: ssa2 = ssa1  (copy propagation — forward the mapping) */
        if (TREE_CODE(rhs) == SSA_NAME) {
            unsigned int src_ver = SSA_NAME_VERSION(rhs);
            const ssa_entry_t *src = ssa_map_get(&g_ssa_map, src_ver);
            if (src)
                ssa_map_put(&g_ssa_map, ver, src->name, src->arg_pos);
            continue;
        }

        /* case D: ssa = indirect MEM_REF / INDIRECT_REF of known field */
        if (TREE_CODE(rhs) == MEM_REF || TREE_CODE(rhs) == INDIRECT_REF) {
            tree inner = TREE_OPERAND(rhs, 0);
            if (inner && TREE_CODE(inner) == SSA_NAME) {
                const ssa_entry_t *src = ssa_map_get(&g_ssa_map,
                                                      SSA_NAME_VERSION(inner));
                if (src)
                    ssa_map_put(&g_ssa_map, ver, src->name, src->arg_pos);
            }
        }

        /* case E: ssa2 = ssa1 & mask  (e.g. type = sock->type & SOCK_TYPE_MASK)
         * Forward the name through bitwise AND/OR with a constant.
         * This is extremely common in the kernel for type masking. */
        {
            enum tree_code rc = gimple_assign_rhs_code(stmt);
            if (rc == BIT_AND_EXPR || rc == BIT_OR_EXPR || rc == BIT_XOR_EXPR) {
                tree op1 = gimple_assign_rhs1(stmt);
                tree op2 = gimple_assign_rhs2(stmt);
                /* one operand should be a constant, the other an SSA name */
                tree ssa_op = NULL;
                if (op1 && TREE_CODE(op1) == SSA_NAME) ssa_op = op1;
                else if (op2 && TREE_CODE(op2) == SSA_NAME) ssa_op = op2;
                if (ssa_op) {
                    const ssa_entry_t *src = ssa_map_get(&g_ssa_map,
                                                          SSA_NAME_VERSION(ssa_op));
                    if (src)
                        ssa_map_put(&g_ssa_map, ver, src->name, src->arg_pos);
                }
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CATEGORY 9: if/else branches (GIMPLE_COND)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int arg_pos_of(tree parm) {
    if (!parm || TREE_CODE(parm) != PARM_DECL) return -1;
    int pos = 0;
    for (tree p = DECL_ARGUMENTS(current_function_decl); p;
         p = DECL_CHAIN(p), pos++) {
        if (p == parm) return pos;
    }
    return -1;
}

static void handle_cond(tu_data_t *td, gcond *stmt,
                        const char *func_name, const char *src_file) {
    (void)src_file;
    tree lhs_t = gimple_cond_lhs(stmt);
    tree rhs_t = gimple_cond_rhs(stmt);
    enum tree_code code = gimple_cond_code(stmt);

    const char *op = NULL;
    switch (code) {
        case EQ_EXPR:  op = "=="; break;
        case NE_EXPR:  op = "!="; break;
        case LT_EXPR:  op = "<";  break;
        case LE_EXPR:  op = "<="; break;
        case GT_EXPR:  op = ">";  break;
        case GE_EXPR:  op = ">="; break;
        default: return;
    }

    long long   rhs_val  = 0;
    const char *lhs_name = NULL;
    int         lhs_pos  = -1;
    const char *rhs_lbl  = NULL;

    /* try RHS as constant first; if not, try swapping sides */
    int rhs_is_const = try_get_int(rhs_t, &rhs_val);
    if (!rhs_is_const) {
        /* try LHS as constant and swap */
        if (try_get_int(lhs_t, &rhs_val)) {
            tree tmp = lhs_t; lhs_t = rhs_t; rhs_t = tmp;
            rhs_is_const = 1;
            /* flip operator for swap */
            if      (code == LT_EXPR) op = ">";
            else if (code == LE_EXPR) op = ">=";
            else if (code == GT_EXPR) op = "<";
            else if (code == GE_EXPR) op = "<=";
        }
    }
    if (!rhs_is_const) return;

    rhs_lbl = const_label(rhs_t);

    STRIP_NOPS(lhs_t);
    if (TREE_CODE(lhs_t) == SSA_NAME) {
        tree var = SSA_NAME_VAR(lhs_t);
        if (var) {
            if (TREE_CODE(var) == PARM_DECL) {
                lhs_pos  = arg_pos_of(var);
                if (DECL_NAME(var))
                    lhs_name = IDENTIFIER_POINTER(DECL_NAME(var));
            } else if (DECL_NAME(var)) {
                lhs_name = IDENTIFIER_POINTER(DECL_NAME(var));
            }
        }
        /* anonymous SSA temp (e.g. from sock->type load) — look up in map */
        if (!lhs_name) {
            unsigned int ver = SSA_NAME_VERSION(lhs_t);
            const ssa_entry_t *entry = ssa_map_get(&g_ssa_map, ver);
            if (entry) {
                lhs_name = entry->name;
                lhs_pos  = entry->arg_pos;
            }
        }
    } else if (TREE_CODE(lhs_t) == PARM_DECL) {
        lhs_pos  = arg_pos_of(lhs_t);
        if (DECL_NAME(lhs_t))
            lhs_name = IDENTIFIER_POINTER(DECL_NAME(lhs_t));
    } else if (TREE_CODE(lhs_t) == VAR_DECL) {
        if (DECL_NAME(lhs_t))
            lhs_name = IDENTIFIER_POINTER(DECL_NAME(lhs_t));
    } else if (TREE_CODE(lhs_t) == COMPONENT_REF) {
        /* struct field comparison: sk->sk_family == AF_INET */
        tree field = TREE_OPERAND(lhs_t, 1);
        if (field && TREE_CODE(field) == FIELD_DECL && DECL_NAME(field))
            lhs_name = IDENTIFIER_POINTER(DECL_NAME(field));
    }

    if (!lhs_name) return;

    emit_branch(td, func_name, op, lhs_name,
                rhs_lbl ? rhs_lbl : "", rhs_val, lhs_pos);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CATEGORY 10: switch/case branches
 * ═══════════════════════════════════════════════════════════════════════════ */

static void handle_switch(tu_data_t *td, gswitch *stmt,
                          const char *func_name) {
    tree index = gimple_switch_index(stmt);
    STRIP_NOPS(index);

    const char *lhs_name = NULL;
    int         lhs_pos  = -1;

    if (TREE_CODE(index) == SSA_NAME) {
        tree var = SSA_NAME_VAR(index);
        if (var && TREE_CODE(var) == PARM_DECL) {
            lhs_pos  = arg_pos_of(var);
            if (DECL_NAME(var))
                lhs_name = IDENTIFIER_POINTER(DECL_NAME(var));
        } else if (var && DECL_NAME(var)) {
            lhs_name = IDENTIFIER_POINTER(DECL_NAME(var));
        }
    } else if (TREE_CODE(index) == PARM_DECL) {
        lhs_pos  = arg_pos_of(index);
        if (DECL_NAME(index))
            lhs_name = IDENTIFIER_POINTER(DECL_NAME(index));
    } else if (TREE_CODE(index) == COMPONENT_REF) {
        /* switch (sk->sk_type) */
        tree field = TREE_OPERAND(index, 1);
        if (field && TREE_CODE(field) == FIELD_DECL && DECL_NAME(field))
            lhs_name = IDENTIFIER_POINTER(DECL_NAME(field));
    }

    if (!lhs_name) return;

    unsigned int n = gimple_switch_num_labels(stmt);
    for (unsigned int i = 0; i < n; i++) {
        tree label = gimple_switch_label(stmt, i);
        if (!label) continue;
        tree low  = CASE_LOW(label);
        tree high = CASE_HIGH(label);
        if (!low) continue; /* default case */

        long long low_val = 0;
        if (!try_get_int(low, &low_val)) continue;

        const char *lbl = const_label(low);
        emit_branch(td, func_name, "==", lhs_name,
                    lbl ? lbl : "", low_val, lhs_pos);

        if (high) {
            long long high_val = 0;
            if (try_get_int(high, &high_val)) {
                const char *hlbl = const_label(high);
                emit_branch(td, func_name, "==", lhs_name,
                            hlbl ? hlbl : "", high_val, lhs_pos);
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main per-function GIMPLE walker
 * ═══════════════════════════════════════════════════════════════════════════ */

static void walk_function(tu_data_t *td) {
    if (!current_function_decl) return;
    const char *caller = fn_name(current_function_decl);
    if (!caller) return;

    const char *src_file = DECL_SOURCE_FILE(current_function_decl);
    struct function *fun = DECL_STRUCT_FUNCTION(current_function_decl);
    if (!fun) return;

    /* build SSA definition map for this function */
    ssa_map_clear(&g_ssa_map);
    basic_block bb;
    FOR_EACH_BB_FN(bb, fun) {
        build_ssa_map_bb(bb);
    }

    FOR_EACH_BB_FN(bb, fun) {
        for (gimple_stmt_iterator gsi = gsi_start_bb(bb);
             !gsi_end_p(gsi); gsi_next(&gsi)) {
            gimple *stmt = gsi_stmt(gsi);
            int         line = stmt_line(stmt);
            const char *file = stmt_file(stmt);
            if (!file) file = src_file;

            switch (gimple_code(stmt)) {
                case GIMPLE_CALL:
                    handle_call(td, as_a<gcall *>(stmt), caller, file, line);
                    break;
                case GIMPLE_ASSIGN:
                    handle_assign(td, as_a<gassign *>(stmt), file, line);
                    break;
                case GIMPLE_COND:
                    handle_cond(td, as_a<gcond *>(stmt), caller, file);
                    break;
                case GIMPLE_SWITCH:
                    handle_switch(td, as_a<gswitch *>(stmt), caller);
                    break;
                default:
                    break;
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * GCC PASS infrastructure
 * ═══════════════════════════════════════════════════════════════════════════ */

namespace {

const pass_data nervo_pass_data = {
    GIMPLE_PASS, "nervo", OPTGROUP_NONE, TV_NONE,
    PROP_ssa, 0, 0, 0, 0
};

class nervo_pass : public gimple_opt_pass {
public:
    nervo_pass(gcc::context *ctx)
        : gimple_opt_pass(nervo_pass_data, ctx) {}

    bool gate(function *) override { return true; }

    unsigned int execute(function *fun) override {
        if (!fun || !fun->decl) return 0;
        if (!current_tu) {
            current_tu          = (tu_data_t *)xmalloc(sizeof(tu_data_t));
            jbuf_init(&current_tu->records);
            current_tu->count   = 0;
        }
        walk_function(current_tu);
        return 0;
    }
};

} /* anonymous namespace */

/* ── manifest writer ────────────────────────────────────────────────────── */
static void append_manifest(const char *abs_path) {
    pthread_mutex_lock(&manifest_mutex);
    FILE *f = fopen(compiled_files_path, "a");
    if (f) { fprintf(f, "%s\n", abs_path); fclose(f); }
    pthread_mutex_unlock(&manifest_mutex);
}

/* ── output file ────────────────────────────────────────────────────────── */
static void mangle_path(const char *src, char *dst, size_t dstlen) {
    size_t i = 0;
    for (const char *p = src; *p && i < dstlen - 1; p++, i++)
        dst[i] = (*p == '/' || *p == '\\') ? '_' : *p;
    dst[i] = '\0';
}

static FILE *open_tu_json(const char *src_file) {
    char mangled[4096], path[8192];
    mangle_path(src_file, mangled, sizeof(mangled));
    snprintf(path, sizeof(path), "%s/%s.json", nervo_out_dir, mangled);
    struct stat st;
    if (stat(nervo_out_dir, &st) != 0) mkdir(nervo_out_dir, 0755);
    FILE *f = fopen(path, "w");
    if (!f)
        warning(0, "nervo: cannot open %s: %s", path, xstrerror(errno));
    return f;
}

/* ── called once per TU just before the compiler exits ─────────────────── */
static void nervo_finish_unit(void * /*gcc_data*/, void * /*user_data*/) {
    if (!current_tu) return;

    /* walk all global variable initializers now that all functions are done */
    walk_globals(current_tu);

    if (current_tu->count == 0) {
        free(current_tu);
        current_tu = NULL;
        return;
    }

    const char *src = main_input_filename;
    if (!src) src = "<unknown>";

    char abs_path[4096] = {0};
    if (!realpath(src, abs_path))
        strncpy(abs_path, src, sizeof(abs_path) - 1);

    append_manifest(abs_path);

    FILE *f = open_tu_json(abs_path);
    if (f) {
        fprintf(f, "[\n%s\n]\n", current_tu->records.buf);
        fclose(f);
    }

    jbuf_free(&current_tu->records);
    free(current_tu);
    current_tu = NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * plugin_init
 * ═══════════════════════════════════════════════════════════════════════════ */
int plugin_init(struct plugin_name_args   *plugin_info,
                struct plugin_gcc_version *version)
{
    if (!plugin_default_version_check(version, &gcc_version)) {
        error("nervo: incompatible GCC version");
        return 1;
    }

    for (int i = 0; i < plugin_info->argc; i++) {
        if (strcmp(plugin_info->argv[i].key, "out") == 0)
            strncpy(nervo_out_dir, plugin_info->argv[i].value,
                    sizeof(nervo_out_dir) - 1);
    }

    const char *env_out = getenv("NERVO_OUT");
    if (env_out)
        strncpy(nervo_out_dir, env_out, sizeof(nervo_out_dir) - 1);

    snprintf(compiled_files_path, sizeof(compiled_files_path),
             "%s/nervo_compiled_files.txt", nervo_out_dir);

    mkdir(nervo_out_dir, 0755);

    struct register_pass_info pass_info;
    pass_info.pass                    = new nervo_pass(g);
    pass_info.reference_pass_name     = "ssa";
    pass_info.ref_pass_instance_number = 1;
    pass_info.pos_op                  = PASS_POS_INSERT_AFTER;
    register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP,
                      NULL, &pass_info);

    register_callback(plugin_info->base_name, PLUGIN_FINISH_UNIT,
                      nervo_finish_unit, NULL);

    inform(UNKNOWN_LOCATION,
           "nervo plugin loaded (full coverage) - output: %s", nervo_out_dir);
    return 0;
}