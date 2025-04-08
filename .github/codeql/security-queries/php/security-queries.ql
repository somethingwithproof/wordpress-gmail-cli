/**
 * @name PHP Security Queries
 * @description Custom security queries for PHP code
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id php/security-queries
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-089
 *       external/cwe/cwe-094
 */

import php

/**
 * Finds instances of unvalidated user input being used in security-sensitive contexts
 */
class UnsafeUserInput extends DataFlow::Node {
  UnsafeUserInput() {
    exists(SuperGlobalVariable sgv |
      sgv.getName() = ["_GET", "_POST", "_REQUEST", "_COOKIE"] and
      this.asExpr() = sgv.getAnArrayAccess()
    )
  }
}

/**
 * Finds instances of unsafe redirects
 */
from FunctionCall fc, UnsafeUserInput input
where
  fc.getTarget().getName() = "wp_redirect" and
  input.getASuccessor*() = fc.getArgument(0).asExpr()
select fc, "Potentially unsafe redirect using unvalidated user input. Use wp_safe_redirect instead."

/**
 * Finds instances of unescaped output
 */
from FunctionCall fc, UnsafeUserInput input
where
  fc.getTarget().getName() = "echo" and
  not exists(FunctionCall esc |
    esc.getTarget().getName() in ["esc_html", "esc_attr", "esc_url", "esc_js"] and
    esc.getASuccessor*() = fc.getArgument(0).asExpr()
  ) and
  input.getASuccessor*() = fc.getArgument(0).asExpr()
select fc, "Potentially unsafe echo of unvalidated user input. Use esc_html or other escaping functions."

/**
 * Finds instances of SQL injection
 */
from FunctionCall fc, UnsafeUserInput input
where
  fc.getTarget().getName() = "query" and
  input.getASuccessor*() = fc.getArgument(0).asExpr() and
  not exists(FunctionCall prep |
    prep.getTarget().getName() in ["prepare", "esc_sql"] and
    prep.getASuccessor*() = fc.getArgument(0).asExpr()
  )
select fc, "Potential SQL injection. Use $wpdb->prepare() for SQL queries with user input."
