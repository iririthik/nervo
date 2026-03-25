/**
 * 01_extract_nodes.sc — Joern script: extract nodes from CPG
 *
 * Environment variables (set before calling joern --script):
 *   NERVO_CPG_FILE  — path to the .cpg binary
 *   NERVO_OUT_FILE  — path to write nodes JSON output
 *
 * Usage:
 *   NERVO_CPG_FILE=out/cpg/net_ipv4.cpg \
 *   NERVO_OUT_FILE=out/json/nodes_net_ipv4.json \
 *   joern --script 01_extract_nodes.sc
 */

val cpgFile = System.getenv("NERVO_CPG_FILE")
val outFile = System.getenv("NERVO_OUT_FILE")

if (cpgFile == null || outFile == null) {
  System.err.println("[01_extract_nodes] ERROR: NERVO_CPG_FILE and NERVO_OUT_FILE must be set")
  System.exit(1)
}

System.err.println(s"[01_extract_nodes] Loading CPG: $cpgFile")
importCpg(cpgFile)
System.err.println(s"[01_extract_nodes] CPG loaded — ${cpg.method.size} methods found")

val records = new scala.collection.mutable.ArrayBuffer[String]()

def jsonStr(s: String): String =
  if (s == null) "null"
  else "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
               .replace("\n", "\\n").replace("\r", "\\r")
               .replace("\t", "\\t") + "\""

def jsonInt(n: Int): String = n.toString

def emit(obj: String): Unit = records += obj

// ── Function nodes ────────────────────────────────────────────────────────────
System.err.println("[01_extract_nodes] Extracting Function nodes...")
cpg.method.foreach { m =>
  emit(
    s"""{ "nodeType": "Function", """ +
    s""""name": ${jsonStr(m.name)}, """ +
    s""""fullName": ${jsonStr(Option(m.fullName).getOrElse(m.name))}, """ +
    s""""file": ${jsonStr(Option(m.filename).getOrElse(""))}, """ +
    s""""line": ${jsonInt(m.lineNumber.getOrElse(-1))}, """ +
    s""""signature": ${jsonStr(Option(m.signature).getOrElse(""))}, """ +
    s""""isExternal": ${m.isExternal} }"""
  )
}
System.err.println(s"[01_extract_nodes]   Functions: ${cpg.method.size}")

// ── Parameter nodes ───────────────────────────────────────────────────────────
System.err.println("[01_extract_nodes] Extracting Parameter nodes...")
cpg.method.foreach { m =>
  m.parameter.foreach { p =>
    emit(
      s"""{ "nodeType": "Parameter", """ +
      s""""functionName": ${jsonStr(m.name)}, """ +
      s""""name": ${jsonStr(Option(p.name).getOrElse(""))}, """ +
      s""""position": ${jsonInt(p.order - 1)}, """ +
      s""""typeFullName": ${jsonStr(Option(p.typeFullName).getOrElse(""))} }"""
    )
  }
}
System.err.println(s"[01_extract_nodes]   Parameters done")

// ── BranchPoint nodes ─────────────────────────────────────────────────────────
System.err.println("[01_extract_nodes] Extracting BranchPoint nodes...")
cpg.method.foreach { m =>
  val fnName = m.name
  m.controlStructure.isIf.condition.foreach { cond =>
    val condCode = Option(cond.code).getOrElse("")
    val opPattern = """(\w+)\s*(==|!=|<=|>=|<|>)\s*(\w+)""".r
    opPattern.findFirstMatchIn(condCode) match {
      case Some(mat) =>
        emit(
          s"""{ "nodeType": "BranchPoint", "branchType": "if", """ +
          s""""function": ${jsonStr(fnName)}, """ +
          s""""conditionOp": ${jsonStr(mat.group(2))}, """ +
          s""""conditionLHS": ${jsonStr(mat.group(1))}, """ +
          s""""conditionRHS": ${jsonStr(mat.group(3))}, """ +
          s""""conditionRHSValue": null, "source": "joern" }"""
        )
      case None =>
        emit(
          s"""{ "nodeType": "BranchPoint", "branchType": "if", """ +
          s""""function": ${jsonStr(fnName)}, """ +
          s""""conditionOp": null, "conditionLHS": null, """ +
          s""""conditionRHS": null, "conditionRHSValue": null, """ +
          s""""rawCondition": ${jsonStr(condCode)}, "source": "joern" }"""
        )
    }
  }
}
System.err.println(s"[01_extract_nodes]   BranchPoints done")

// ── IndirectCall nodes ────────────────────────────────────────────────────────
System.err.println("[01_extract_nodes] Extracting IndirectCall nodes...")
cpg.call.foreach { c =>
  val isIndirect = c.callee.size == 0 || c.methodFullName == "<operator>.indirectCall"
  if (isIndirect) {
    emit(
      s"""{ "nodeType": "IndirectCall", """ +
      s""""callerFunction": ${jsonStr(c.method.name)}, """ +
      s""""callExpression": ${jsonStr(Option(c.code).getOrElse(""))}, """ +
      s""""file": ${jsonStr(Option(c.file.name.headOption.getOrElse("")).getOrElse(""))}, """ +
      s""""line": ${jsonInt(c.lineNumber.getOrElse(-1))} }"""
    )
  }
}
System.err.println(s"[01_extract_nodes]   IndirectCalls done")

// ── FnPtrAssignment nodes ─────────────────────────────────────────────────────
System.err.println("[01_extract_nodes] Extracting FnPtrAssignment nodes...")
cpg.assignment.foreach { a =>
  val lhsCode = Option(a.source.code).getOrElse("")
  val addrOf  = """&(\w+)""".r
  addrOf.findFirstMatchIn(lhsCode) match {
    case Some(mat) =>
      val targetFn   = mat.group(1)
      val rhsCode    = Option(a.target.code).getOrElse("")
      val fieldPat   = """(\w+)\.(\w+)""".r
      val arrayPat   = """(\w+)\[(\d+)\]""".r
      fieldPat.findFirstMatchIn(rhsCode) match {
        case Some(fm) =>
          emit(
            s"""{ "nodeType": "FnPtrAssignment", """ +
            s""""structType": null, "fieldName": ${jsonStr(fm.group(2))}, """ +
            s""""targetFn": ${jsonStr(targetFn)}, """ +
            s""""sourceFile": ${jsonStr(Option(a.file.name.headOption.getOrElse("")).getOrElse(""))}, """ +
            s""""line": ${jsonInt(a.lineNumber.getOrElse(-1))}, """ +
            s""""arrayIndex": null, "source": "joern" }"""
          )
        case None =>
          arrayPat.findFirstMatchIn(rhsCode) match {
            case Some(am) =>
              emit(
                s"""{ "nodeType": "FnPtrAssignment", """ +
                s""""structType": null, "fieldName": ${jsonStr(am.group(1))}, """ +
                s""""targetFn": ${jsonStr(targetFn)}, """ +
                s""""sourceFile": ${jsonStr(Option(a.file.name.headOption.getOrElse("")).getOrElse(""))}, """ +
                s""""line": ${jsonInt(a.lineNumber.getOrElse(-1))}, """ +
                s""""arrayIndex": ${am.group(2)}, "source": "joern" }"""
              )
            case None =>
          }
      }
    case None =>
  }
}
System.err.println(s"[01_extract_nodes]   FnPtrAssignments done")

// ── write output ──────────────────────────────────────────────────────────────
System.err.println(s"[01_extract_nodes] Writing ${records.size} nodes to $outFile")
val pw = new java.io.FileWriter(outFile)
pw.write("[\n")
pw.write(records.mkString(",\n"))
pw.write("\n]\n")
pw.close()
System.err.println(s"[01_extract_nodes] Done → $outFile")

exit