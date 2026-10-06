# @summary A CrowdSec AppSec hook entry (on_load, pre_eval, post_eval, on_match).
#
# `apply` holds the expr-lang statements to run, `filter` an optional
# expression restricting when they run.
type Crowdsec::AppsecHook = Struct[{
    Optional['filter'] => String[1],
    'apply'            => Array[String[1], 1],
}]
