/**
 * 02_extract_edges.sc — Joern script: extract edges from CPG
 *
 * Environment variables (set before calling joern --script):
 *   NERVO_CPG_FILE  — path to the .cpg binary
 *   NERVO_OUT_FILE  — path to write edges JSON output
 *
 * Usage:
 *   NERVO_CPG_FILE=out/cpg/net_ipv4.cpg \
 *   NERVO_OUT_FILE=out/json/edges_net_ipv4.json \
 *   joern --script 02_extract_edges.sc
 */

val cpgFile = System.getenv("NERVO_CPG_FILE")
val outFile = System.getenv("NERVO_OUT_FILE")

if (cpgFile == null || outFile == null) {
  System.err.println("[02_extract_edges] ERROR: NERVO_CPG_FILE and NERVO_OUT_FILE must be set")
  System.exit(1)
}

System.err.println(s"[02_extract_edges] Loading CPG: $cpgFile")
importCpg(cpgFile)
System.err.println(s"[02_extract_edges] CPG loaded — ${cpg.method.size} methods found")

val records = new scala.collection.mutable.ArrayBuffer[String]()

def jsonStr(s: String): String =
  if (s == null) "null"
  else "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
               .replace("\n", "\\n").replace("\r", "\\r")
               .replace("\t", "\\t") + "\""

def jsonInt(n: Int): String = n.toString

def emit(obj: String): Unit = records += obj

// ── CallEdge ──────────────────────────────────────────────────────────────────
System.err.println("[02_extract_edges] Extracting CallEdges...")
cpg.call.foreach { c =>
  val callees = c.callee.l
  if (callees.nonEmpty) {
    val caller     = c.method.name
    val callerFile = Option(c.file.name.headOption.getOrElse("")).getOrElse("")
    val line       = c.lineNumber.getOrElse(-1)
    callees.foreach { callee =>
      val calleeName = callee.name
      if (!calleeName.startsWith("<operator>") && !calleeName.startsWith("__builtin_")) {
        emit(
          s"""{ "edgeType": "CallEdge", """ +
          s""""callerFn": ${jsonStr(caller)}, """ +
          s""""calleeFn": ${jsonStr(calleeName)}, """ +
          s""""file": ${jsonStr(callerFile)}, """ +
          s""""line": ${jsonInt(line)}, """ +
          s""""source": "joern" }"""
        )
      }
    }
  }
}
System.err.println(s"[02_extract_edges]   CallEdges done")

// ── DataFlowEdge ──────────────────────────────────────────────────────────────
System.err.println("[02_extract_edges] Extracting DataFlowEdges...")
cpg.call.foreach { c =>
  val callees = c.callee.l
  if (callees.nonEmpty) {
    val caller = c.method.name
    callees.foreach { callee =>
      val calleeName = callee.name
      if (!calleeName.startsWith("<operator>") && !calleeName.startsWith("__builtin_")) {
        c.argument.foreach { arg =>
          val argPos  = arg.order - 1
          val argCode = Option(arg.code).getOrElse("")
          callee.parameter.find(_.order - 1 == argPos).foreach { param =>
            emit(
              s"""{ "edgeType": "DataFlowEdge", """ +
              s""""callerFn": ${jsonStr(caller)}, """ +
              s""""calleeFn": ${jsonStr(calleeName)}, """ +
              s""""callerArgPos": ${jsonInt(argPos)}, """ +
              s""""calleeParamPos": ${jsonInt(param.order - 1)}, """ +
              s""""callerArgCode": ${jsonStr(argCode)}, """ +
              s""""calleeParamName": ${jsonStr(Option(param.name).getOrElse(""))} }"""
            )
          }
        }
      }
    }
  }
}
System.err.println(s"[02_extract_edges]   DataFlowEdges done")

// ── IndirectCallEdge ──────────────────────────────────────────────────────────
System.err.println("[02_extract_edges] Extracting IndirectCallEdges...")
cpg.call.foreach { c =>
  val isIndirect = c.callee.size == 0 || c.methodFullName == "<operator>.indirectCall"
  if (isIndirect) {
    val argCodes = c.argument.l.sortBy(_.order)
      .map(a => jsonStr(Option(a.code).getOrElse("")))
      .mkString(", ")
    emit(
      s"""{ "edgeType": "IndirectCallEdge", """ +
      s""""callerFn": ${jsonStr(c.method.name)}, """ +
      s""""callExpression": ${jsonStr(Option(c.code).getOrElse(""))}, """ +
      s""""file": ${jsonStr(Option(c.file.name.headOption.getOrElse("")).getOrElse(""))}, """ +
      s""""line": ${jsonInt(c.lineNumber.getOrElse(-1))}, """ +
      s""""argCount": ${c.argument.size}, """ +
      s""""argCodes": [$argCodes] }"""
    )
  }
}
System.err.println(s"[02_extract_edges]   IndirectCallEdges done")

// ── write output ──────────────────────────────────────────────────────────────
System.err.println(s"[02_extract_edges] Writing ${records.size} edges to $outFile")
val pw = new java.io.FileWriter(outFile)
pw.write("[\n")
pw.write(records.mkString(",\n"))
pw.write("\n]\n")
pw.close()
System.err.println(s"[02_extract_edges] Done → $outFile")

exit