/**
 * @name JavaScript Security Queries
 * @description Custom security queries for JavaScript code
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id js/security-queries
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-094
 */

import javascript
import semmle.javascript.security.dataflow.DomBasedXss
import semmle.javascript.security.dataflow.CodeInjection
import semmle.javascript.security.dataflow.CommandInjection

/**
 * Finds instances of DOM-based XSS
 */
from DomBasedXss::Configuration config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential DOM-based XSS vulnerability. User input reaches a dangerous sink without proper sanitization."

/**
 * Finds instances of code injection
 */
from CodeInjection::Configuration config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential code injection vulnerability. User input is used in a code execution context."

/**
 * Finds instances of command injection
 */
from CommandInjection::Configuration config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential command injection vulnerability. User input is used in a command execution context."

/**
 * Finds instances of insecure use of eval
 */
from CallExpr eval
where eval.getCalleeName() = "eval"
select eval, "Use of eval is potentially dangerous and can lead to code injection vulnerabilities."

/**
 * Finds instances of insecure use of innerHTML
 */
from PropAccess pa, DataFlow::Node source
where 
  pa.getPropertyName() = "innerHTML" and
  exists(DataFlow::Node input |
    input.asExpr() = pa.getBase() and
    source.getASuccessor*() = input
  ) and
  source instanceof DataFlow::SourceNode
select pa, "Potentially unsafe assignment to innerHTML. Consider using textContent or DOM methods instead."

/**
 * Finds instances of insecure use of localStorage without validation
 */
from PropAccess pa, DataFlow::Node source
where 
  pa.getPropertyName() = "localStorage" and
  exists(CallExpr getItem |
    getItem.getCallee().(PropAccess).getBase() = pa and
    getItem.getCallee().(PropAccess).getPropertyName() = "getItem" and
    not exists(IfStmt ifCheck |
      ifCheck.getCondition().getAChildExpr*() = getItem
    )
  )
select pa, "Use of localStorage without proper validation can lead to security issues."
