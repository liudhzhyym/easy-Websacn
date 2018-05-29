from .model.information.informationmain import *

informationpocdict = {
    "options方法开启": options_method_BaseVerify,
    "git源码泄露扫描": git_check_BaseVerify,
    "java配置文件文件发现": jsp_conf_find_BaseVerify,
    "robots文件发现": robots_find_BaseVerify,
    "svn源码泄露扫描": svn_check_BaseVerify,
    "JetBrains IDE workspace.xml文件泄露": jetbrains_ide_workspace_disclosure_BaseVerify,
    "apache server-status信息泄露": apache_server_status_disclosure_BaseVerify,
    "crossdomain.xml文件发现": crossdomain_find_BaseVerify,
}
