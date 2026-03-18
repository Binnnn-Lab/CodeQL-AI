/**
 * @name Find Taint Path (C/C++)
 * @description Trace taint path from source to sink.
 * @kind problem
 * @id cpp/taint-tracking/find-taint-path
 * @problem.severity warning
 * @
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow



predicate sourceMatchLocation(DataFlow::Node node) {
  exists(string path | 
    path = node.getLocation().getFile().getAbsolutePath() and
    path.matches("%CWE190_Integer_Overflow__char_fscanf_add_83_goodB2G.cpp")
  ) and
  node.getLocation().getStartLine() = 28 and
  (
    node.toString().matches("%fscanf%") or
    node.asExpr().toString().matches("%fscanf%") or
    exists(FunctionCall fc | 
      fc.getTarget().getName().matches("%fscanf%") and 
      fc.getLocation().getStartLine() = node.getLocation().getStartLine() and
      (fc.getAnArgument() = node.asExpr() or fc = node.asExpr())
    )
  )
}

predicate sinkMatchLocation(DataFlow::Node node) {
  exists(string path | 
    path = node.getLocation().getFile().getAbsolutePath() and
    path.matches("%CWE190_Integer_Overflow__char_fscanf_add_83_goodB2G.cpp")
  ) and
  node.getLocation().getStartLine() = 36
  and
  (
    node.toString().matches("%data%") or
    node.asExpr().toString().matches("%data%") or
    exists(FunctionCall fc | 
      fc.getTarget().getName().matches("%data%") and 
      fc.getLocation().getStartLine() = node.getLocation().getStartLine() and
      (fc.getAnArgument() = node.asExpr() or fc = node.asExpr())
    )
  )
}


module TraceConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    sourceMatchLocation(source)
  }

  predicate isSink(DataFlow::Node sink) {
    sinkMatchLocation(sink)
  }
}

module AnyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string path | 
      path = source.getLocation().getFile().getAbsolutePath() and
      path.matches("%CWE190_Integer_Overflow__char_fscanf_add_83_goodB2G.cpp")
    ) and
    source.getLocation().getStartLine() = 28 and
    (
      source.toString().matches("%fscanf%") or
      source.asExpr().toString().matches("%fscanf%") or
      exists(FunctionCall fc | 
        fc.getTarget().getName().matches("%fscanf%") and 
        fc.getLocation().getStartLine() = source.getLocation().getStartLine() and
        (fc.getAnArgument() = source.asExpr() or fc = source.asExpr())
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    1=1
  }
}


module MyFlow = TaintTracking::Global<TraceConfig>;

module AnyFlow = TaintTracking::Global<AnyConfig>;

from DataFlow::Node source, DataFlow::Node sink, Function func, DataFlow::Node mid
where 
MyFlow::flow(source, sink) and 
AnyFlow::flow(source, mid) 
and
(
  exists(FunctionCall fc | 
    fc.getAnArgument() = mid.asExpr() and 
    func = fc.getTarget()
  )
  or
  exists(FunctionCall fc | 
    fc = mid.asExpr() and 
    func = fc.getTarget()
  )
  or 
  (func = mid.asExpr().getEnclosingFunction())
)
select mid, "function: " + func.getName()
