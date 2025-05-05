/**
 * @name WordPress Security Vulnerabilities
 * @description Detects common WordPress security vulnerabilities
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id php/wordpress-security-vulnerabilities
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-089
 *       external/cwe/cwe-094
 *       external/cwe/cwe-352
 *       external/cwe/cwe-434
 *       external/cwe/cwe-601
 */

import php
import semmle.code.php.Security
import semmle.code.php.frameworks.WordPress

/**
 * Class representing potentially unsafe user input
 */
class WordPressUserInput extends DataFlow::Node {
  WordPressUserInput() {
    exists(SuperGlobalVariable sgv |
      sgv.getName() = ["_GET", "_POST", "_REQUEST", "_COOKIE"] and
      this.asExpr() = sgv.getAnArrayAccess()
    )
    or
    exists(FunctionCall fc |
      fc.getTarget().getName() in [
        "get_query_var", "wp_unslash", "get_option", "get_post_meta", "get_user_meta"
      ] and
      this.asExpr() = fc
    )
  }
}

/**
 * Detect unescaped output in WordPress
 */
from FunctionCall fc, WordPressUserInput input
where
  // Direct echo or print without escaping
  (
    fc.getTarget().getName() in ["echo", "print"] and
    not exists(FunctionCall esc |
      esc.getTarget().getName() in [
        "esc_html", "esc_attr", "esc_url", "esc_js", "wp_kses", "wp_kses_post"
      ] and
      DataFlow::exprNode(esc).getASuccessor*() = DataFlow::exprNode(fc.getArgument(0))
    ) and
    DataFlow::exprNode(input).getASuccessor*() = DataFlow::exprNode(fc.getArgument(0))
  )
select fc, "Potentially unsafe output of user input without escaping. Use esc_html() or similar functions."

/**
 * Detect SQL injections in WordPress
 */
from MethodCall mc, WordPressUserInput input
where
  // WordPress database query without preparation
  mc.getMethodName() in ["query", "get_results", "get_row", "get_col", "get_var"] and
  mc.getQualifier().toString().regexpMatch(".*\\$wpdb.*") and
  not exists(MethodCall prep |
    prep.getMethodName() = "prepare" and
    prep.getQualifier().toString().regexpMatch(".*\\$wpdb.*") and
    DataFlow::exprNode(prep).getASuccessor*() = DataFlow::exprNode(mc.getArgument(0))
  ) and
  not exists(FunctionCall esc |
    esc.getTarget().getName() = "esc_sql" and
    DataFlow::exprNode(esc).getASuccessor*() = DataFlow::exprNode(mc.getArgument(0))
  ) and
  DataFlow::exprNode(input).getASuccessor*() = DataFlow::exprNode(mc.getArgument(0))
select mc, "Potential SQL injection vulnerability. Use $wpdb->prepare() for dynamic SQL queries."

/**
 * Detect Cross-Site Request Forgery (CSRF) vulnerabilities
 */
from FunctionCall fc
where
  // Operations that modify data but don't verify nonce
  fc.getTarget().getName() in [
    "update_option", "add_option", "delete_option", "update_post_meta", "update_user_meta"
  ] and
  not exists(FunctionCall nonce |
    nonce.getTarget().getName() in ["check_admin_referer", "check_ajax_referer", "wp_verify_nonce"] and
    nonce.getEnclosingFunction() = fc.getEnclosingFunction()
  )
select fc, "Potential CSRF vulnerability. Use wp_verify_nonce() or check_admin_referer() for data modification."

/**
 * Detect unsafe file uploads
 */
from MethodCall mc, ArrayAccess aa
where
  // File upload handling without proper checks
  mc.getMethodName() = "move_uploaded_file" and
  aa.getArray().toString() = "$_FILES" and
  not exists(FunctionCall valid |
    valid.getTarget().getName() in ["wp_handle_upload", "wp_handle_sideload"] and
    valid.getEnclosingFunction() = mc.getEnclosingFunction()
  )
select mc, "Unsafe file upload handling. Use wp_handle_upload() with proper MIME type validation."

/**
 * Detect unsafe redirects
 */
from FunctionCall fc, WordPressUserInput input
where
  // Unsafe redirects with user input
  fc.getTarget().getName() in ["wp_redirect", "wp_safe_redirect"] and
  DataFlow::exprNode(input).getASuccessor*() = DataFlow::exprNode(fc.getArgument(0)) and
  not exists(FunctionCall valid |
    valid.getTarget().getName() in ["wp_validate_redirect", "esc_url_raw"] and
    DataFlow::exprNode(valid).getASuccessor*() = DataFlow::exprNode(fc.getArgument(0))
  )
select fc, "Unsafe redirect with user input. Use wp_validate_redirect() to sanitize the destination URL."

/**
 * Detect inadequate capability checks
 */
from FunctionCall fc
where
  // Admin functions without proper capability checks
  fc.getTarget().getName() in [
    "register_post_type", "register_taxonomy", "add_menu_page", "add_submenu_page", "add_management_page",
    "add_options_page", "add_theme_page", "add_plugins_page", "add_users_page", "add_dashboard_page"
  ] and
  not exists(FunctionCall cap |
    cap.getTarget().getName() in ["current_user_can", "is_admin", "check_admin_referer"] and
    cap.getEnclosingFunction() = fc.getEnclosingFunction()
  )
select fc, "Missing capability check for admin functionality. Use current_user_can() to verify permissions."