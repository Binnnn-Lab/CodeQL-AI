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
    path.matches("%&source_file_path&")
  ) and
  node.getLocation().getStartLine() = &source_start_line& and
  (
    node.toString().matches("%&source_target_name&%") or
    node.asExpr().toString().matches("%&source_target_name&%") or
    exists(FunctionCall fc | 
      fc.getTarget().getName().matches("%&source_target_name&%") and 
      fc.getLocation().getStartLine() = node.getLocation().getStartLine() and
      (fc.getAnArgument() = node.asExpr() or fc = node.asExpr())
    )
  )
}

predicate sinkMatchLocation(DataFlow::Node node) {
  exists(string path | 
    path = node.getLocation().getFile().getAbsolutePath() and
    path.matches("%&sink_file_path&")
  ) and
  node.getLocation().getStartLine() = &sink_start_line&
  and
  (
    node.toString().matches("%&sink_target_name&%") or
    node.asExpr().toString().matches("%&sink_target_name&%") or
    exists(FunctionCall fc | 
      fc.getTarget().getName().matches("%&sink_target_name&%") and 
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
      path.matches("%&source_file_path&")
    ) and
    source.getLocation().getStartLine() = &source_start_line& and
    (
      source.toString().matches("%&source_target_name&%") or
      source.asExpr().toString().matches("%&source_target_name&%") or
      exists(FunctionCall fc | 
        fc.getTarget().getName().matches("%&source_target_name&%") and 
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
