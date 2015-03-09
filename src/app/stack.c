
#include "include/fastpath.h"

#define FASTPATH_STACK_CONFIG   "./stack.xml"

struct module_entry {
    uint32_t param1;
    uint32_t param2;
    struct module *module;
    LIST_ENTRY(module_entry) entry;
};

LIST_HEAD(, module_entry) module_list;

uint32_t port_map[ROUTE_MAX_LINK] = {0};

void module_add(struct module *module, uint32_t param1, uint32_t param2);
void print_modules(void);
struct module_entry *module_find(const char *name);

static int execute_cmd(char *cmd)
{
    int retry = 0;

    fastpath_log_debug("execute_cmd: %s\n", cmd);
    
    while (retry < 3 && system(cmd) != 0) {
        retry++;
    }
    if (retry == 3) {
        fastpath_log_error("execute %s failed\n", cmd);
        return -1;
    }

    return 0;
}

static void init_port_map(uint32_t ifidx, const char *name)
{
    int fd, err;
    struct ifreq ifr;
    
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    err = ioctl(fd, SIOCGIFINDEX, &ifr);
    close(fd);
    
    if (err) {
        fastpath_log_error("get %s ifidx failed\n", name);
        return;
    }
    
    port_map[ifidx] = ifr.ifr_ifindex;

    fastpath_log_debug("interface %d ifidx %d\n", ifidx, port_map[ifidx]);
}

uint32_t get_port_map(uint32_t ifidx)
{
    uint32_t i;

    for (i = 0; i < ROUTE_MAX_LINK; i++) {
        if (port_map[i] == ifidx) {
            break;
        }
    }

    return i;
}

xmlNodePtr xml_get_child(xmlNodePtr node, const char *name)
{
    xmlNodePtr cur = node->children;

    while (cur) {
        if (cur->type == XML_ELEMENT_NODE && (!xmlStrcmp(cur->name, (const xmlChar *)name))) {
            return cur;
        }
        cur = cur->next;
    }

    return NULL;
}

const char * xml_get_param(xmlNodePtr node, const char *name, const char* def_val)
{
    xmlNodePtr nd, txnd;

    if (node == NULL) {
        return def_val;
    }

    nd = xml_get_child(node, name);
    if (nd == NULL) {
        return def_val;
    }

    txnd = nd->children;
    if (txnd == NULL || txnd->type != XML_TEXT_NODE || txnd->content == NULL) {
        return def_val;
    }

    return (const char *)txnd->content;
}

xmlXPathObjectPtr xml_get_nodeset(xmlXPathContextPtr context, const char *path)
{
    xmlXPathObjectPtr result;

    result = xmlXPathEvalExpression((const xmlChar *)path, context);
    if (result == NULL) {
        printf("%s: xmlXPathEvalExpression return NULL.\n", __func__);
        return NULL;
    }

    if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
        xmlXPathFreeObject(result);
        return NULL;
    }

    return result;
}

xmlNodePtr xml_get_node(xmlXPathContextPtr context, const char *path, int *dup)
{
    xmlXPathObjectPtr result;
    xmlNodePtr node;

    result = xml_get_nodeset(context, path);
    if (result == NULL) {
        return NULL;
    }

    if (result->nodesetval->nodeNr != 1) {
        printf("%s: duplicate node.[%s]\n", __func__, path);
        xmlXPathFreeObject(result);
        if (dup) {
            *dup = 1;
        }
        return NULL;
    }

    node = result->nodesetval->nodeTab[0];
    xmlXPathFreeObject(result);

    return node;
}

void module_add(struct module *module, uint32_t param1, uint32_t param2)
{
    struct module_entry *entry;

    if (module == NULL) {
        fastpath_log_error("module_add: invalid module\n");
        return;
    }

    entry = rte_malloc(NULL, sizeof(struct module_entry), 0);
    if (entry == NULL) {
        fastpath_log_error("module_add: malloc failed\n");
        return;
    }

    entry->module = module;
    entry->param1 = param1;
    entry->param2 = param2;

    LIST_INSERT_HEAD(&module_list, entry, entry);
}

void print_modules(void)
{
    struct module_entry *entry;

    fastpath_log_info("start to print modules\n");
    
    LIST_FOREACH(entry, &module_list, entry) {
        fastpath_log_info("%s\n", entry->module->name);
    }
}

struct module *module_get_by_name(const char *name)
{
    struct module_entry *entry;
    
    LIST_FOREACH(entry, &module_list, entry) {
        if (strcmp(entry->module->name, name) == 0) {
            return entry->module;
        }
    }

    return NULL;
}

struct module_entry *module_find(const char *name)
{
    struct module_entry *entry;
    
    LIST_FOREACH(entry, &module_list, entry) {
        if (strcmp(entry->module->name, name) == 0) {
            return entry;
        }
    }

    return NULL;
}

void fastpath_init_stack(void)
{
    int i;
    const char *str;
    char expr[256];
    struct module *module;
    struct module_entry *entry;
    xmlDocPtr   doc = NULL; 
    xmlNodePtr  node;
    xmlXPathObjectPtr nodeset;
    xmlXPathContextPtr context = NULL;

    fastpath_log_info("stack setup start\n");

    doc = xmlReadFile(FASTPATH_STACK_CONFIG, NULL, XML_PARSE_NOBLANKS);
    if (doc == NULL) {
        fastpath_log_error("stack_setup: read config file failed\n");
        goto err_out;
    }
    
    if (xmlDocGetRootElement(doc) == NULL) {
        fastpath_log_error("stack_setup: get root element\n");
        goto err_out;
    }
    
    context = xmlXPathNewContext(doc);
    if (context == NULL) {
        fastpath_log_error("stack_setup: get context failed\n");
        goto err_out;
    }

    /* ethernet */
    nodeset = xml_get_nodeset(context, "//port-list/ethernet");
    if (nodeset == NULL) {
        fastpath_log_error("get ethernet failed\n");
        goto err_out;
    }
    for (i = 0; i < nodeset->nodesetval->nodeNr; i++) {
        uint32_t port, mode, native;
        
        node = nodeset->nodesetval->nodeTab[i];

        str = xml_get_param(node, "name", NULL);
        port = strtoul(&str[4], NULL, 0);
        str = xml_get_param(node, "mode", NULL);
        if (strcmp(str, "trunk") == 0) {
            mode = VLAN_MODE_TRUNK;
        } else if (strcmp(str, "access") == 0) {
            mode = VLAN_MODE_ACCESS;
        }
        str = xml_get_param(node, "native", NULL);
        native = strtoul(str, NULL, 0);
        
        module = ethernet_init(port, mode, native);
        module_add(module, port, 0);

        snprintf(expr, sizeof(expr), "ifconfig %s up", module->name);
        if (execute_cmd(expr) < 0) {
            goto err_out;
        }
    }

    /* bridge */
    nodeset = xml_get_nodeset(context, "//bridge-list/bridge");
    if (nodeset == NULL) {
        fastpath_log_error("get bridge failed\n");
        goto err_out;
    }
    for (i = 0; i < nodeset->nodesetval->nodeNr; i++) {
        uint16_t pid, vid;
        xmlNodePtr member;
        
        node = nodeset->nodesetval->nodeTab[i];

        str = xml_get_param(node, "name", NULL);
        snprintf(expr, sizeof(expr), "brctl addbr %s", str);
        if (execute_cmd(expr) < 0) {
            goto err_out;
        }

        snprintf(expr, sizeof(expr), "ifconfig %s up", str);
        if (execute_cmd(expr) < 0) {
            goto err_out;
        }

        str = xml_get_param(node, "vlan", NULL);
        vid = strtoul(str, NULL, 0);

        for (member = node->children; member; member = member->next) {
            if (!strcmp((const char *)member->name, "port")) {
                pid = strtoul((const char *)&member->children->content[4], NULL, 0);

                snprintf(expr, sizeof(expr), "//port-list/ethernet[name='%s']/native", 
                    member->children->content);
                node = xml_get_node(context, expr, NULL);
                if (strtoul((const char *)node->children->content, NULL, 0) == vid) {
                    continue;
                }
                
                snprintf(expr, sizeof(expr), "%s.%d", member->children->content, vid);
                if (module_find(expr) == NULL) {
                    module = vlan_init(pid, vid);
                    module_add(module, vid, 0);

                    snprintf(expr, sizeof(expr), "vconfig add %s %d", member->children->content, vid);
                    if (execute_cmd(expr) < 0) {
                        goto err_out;
                    }

                    snprintf(expr, sizeof(expr), "ifconfig %s.%d up", member->children->content, vid);
                    if (execute_cmd(expr) < 0) {
                        goto err_out;
                    }
                }
            }
        }

        module = bridge_init(vid);
        module_add(module, vid, 0);
    }

    /* interface */
    nodeset = xml_get_nodeset(context, "//interface-list/interface");
    if (nodeset == NULL || nodeset->nodesetval->nodeNr > ROUTE_MAX_LINK) {
        fastpath_log_error("get interface failed\n");
        goto err_out;
    }
    for (i = 0; i < nodeset->nodesetval->nodeNr; i++) {
        uint32_t ifidx;
        
        node = nodeset->nodesetval->nodeTab[i];

        str = xml_get_param(node, "name", NULL);
        ifidx = strtoul(&str[3], NULL, 0);

        module = interface_init(ifidx);
        module_add(module, ifidx, 0);

        snprintf(expr, sizeof(expr), "//bridge-list/bridge[interface='%s']", module->name);
        node = xml_get_node(context, expr, NULL);
        str = xml_get_param(node, "name", NULL);
        init_port_map(ifidx, str);
    }

    /* tcm */
    nodeset = xml_get_nodeset(context, "//tcm-list/tcm");
    if (nodeset != NULL) {
        for (i = 0; i < nodeset->nodesetval->nodeNr; i++) {
            uint32_t ifidx;
            
            node = nodeset->nodesetval->nodeTab[i];

            str = xml_get_param(node, "interface", NULL);
            snprintf(expr, sizeof(expr), "//interface-list/interface[name='%s']", str);
            node = xml_get_node(context, expr, NULL);
            str = xml_get_param(node, "name", NULL);
            ifidx = strtoul(&str[3], NULL, 0);
        
            module = tcm_init(ifidx, 2);
            module_add(module, ifidx, 0);
        }
    }

    /* acl */
    nodeset = xml_get_nodeset(context, "//acl-list/acl");
    if (nodeset != NULL) {
        for (i = 0; i < nodeset->nodesetval->nodeNr; i++) {
            uint32_t ifidx;
            
            node = nodeset->nodesetval->nodeTab[i];

            str = xml_get_param(node, "interface", NULL);
            snprintf(expr, sizeof(expr), "//interface-list/interface[name='%s']", str);
            node = xml_get_node(context, expr, NULL);
            str = xml_get_param(node, "name", NULL);
            ifidx = strtoul(&str[3], NULL, 0);
        
            module = acl_init(ifidx);
            module_add(module, ifidx, 0);
        }
    }

    /* ip route */
    module = route_init();
    module_add(module, 0, 0);

    /* connect modules */
    nodeset = xml_get_nodeset(context, "//ip-forward/interface");
    if (nodeset != NULL) {
        const char *ifname;
        struct module *route, *acl, *tcm, *eif;

        

        entry = module_find("route");
        if (entry == NULL) {
            fastpath_log_error("route module not found\n");
            goto err_out;
        }
        route = entry->module;
        
        for (i = 0; i < nodeset->nodesetval->nodeNr; i++) {
            node = nodeset->nodesetval->nodeTab[i];

            ifname = (const char *)node->children->content;

            acl = tcm = NULL;

            snprintf(expr, sizeof(expr), "//tcm-list/tcm[interface='%s']", ifname);
            node = xml_get_node(context, expr, NULL);
            if (node != NULL) {
                str = xml_get_param(node, "name", NULL);
                entry = module_find(str);
                if (entry == NULL) {
                    fastpath_log_error("tcm module %s not found\n", str);
                }

                tcm = entry->module;
                route->connect(route, tcm, &entry->param1); 
            }

            snprintf(expr, sizeof(expr), "//acl-list/acl[interface='%s']", ifname);
            node = xml_get_node(context, expr, NULL);
            if (node != NULL) {
                str = xml_get_param(node, "name", NULL);
                entry = module_find(str);
                if (entry == NULL) {
                    fastpath_log_error("acl module %s not found\n", str);
                }

                acl = entry->module;
                if (tcm) {
                    tcm->connect(tcm, acl, &entry->param1);
                } else {
                    route->connect(route, acl, &entry->param1);
                }
            }

            entry = module_find(ifname);
            if (entry == NULL) {
                fastpath_log_error("interface module %s not found\n", 
                    node->children->content);
            }
            eif = entry->module;

            if (acl) {
                acl->connect(acl, eif, &entry->param1);
            } else if (tcm) {
                tcm->connect(tcm, eif, &entry->param1);
            } else {
                route->connect(route, eif, &entry->param1); 
            }
        }
    }

    nodeset = xml_get_nodeset(context, "//interface-list/interface");
    if (nodeset != NULL) {
        struct module *eif;
        struct module *br;
        const char *addr_str;

        for (i = 0; i < nodeset->nodesetval->nodeNr; i++) {
            node = nodeset->nodesetval->nodeTab[i];

            str = xml_get_param(node, "name", NULL);
            addr_str = xml_get_param(node, "address", NULL);
            entry = module_find(str);
            eif = entry->module;

            snprintf(expr, 256, "//bridge-list/bridge[interface='%s']", str);
            node = xml_get_node(context, expr, NULL);
            str = xml_get_param(node, "name", NULL);
            entry = module_find(str);
            br = entry->module;

            eif->connect(eif, br, NULL);

            if (addr_str) {
                if (NULL == strchr(addr_str, ':')) {
                    snprintf(expr, sizeof(expr), "ip addr add %s broadcast + dev %s", addr_str, br->name);
                } else {
                    snprintf(expr, sizeof(expr), "ip -6 addr add %s dev %s", addr_str, br->name);
                }
            }
            if (execute_cmd(expr) < 0) {
                goto err_out;
            }
        }
    }

    nodeset = xml_get_nodeset(context, "//bridge-list/bridge");
    for (i = 0; i < nodeset->nodesetval->nodeNr; i++) {
        uint32_t vid, pid = 0;
        xmlNodePtr member;
        struct module *br, *vlan, *eth;
        
        node = nodeset->nodesetval->nodeTab[i];

        str = xml_get_param(node, "name", NULL);
        entry = module_find(str);
        br = entry->module;

        str = xml_get_param(node, "vlan", NULL);
        vid = strtoul(str, NULL, 0);

        for (member = node->children; member; member = member->next) {
            if (!strcmp((const char *)member->name, "port")) {
                snprintf(expr, sizeof(expr), "//port-list/ethernet[name='%s']/native", 
                    member->children->content);
                node = xml_get_node(context, expr, NULL);
                if (strtoul((const char *)node->children->content, NULL, 0) == vid) {
                    entry = module_find((const char *)member->children->content);
                    eth = entry->module;

                    br->connect(br, eth, &pid);
                    pid++;

                    snprintf(expr, sizeof(expr), "brctl addif %s %s", br->name, eth->name);
                    if (execute_cmd(expr) < 0) {
                        goto err_out;
                    }
                } else {
                    snprintf(expr, sizeof(expr), "%s.%d", member->children->content, vid);
                    entry = module_find(expr);
                    vlan = entry->module;

                    entry = module_find((const char *)member->children->content);
                    eth = entry->module;
                    
                    br->connect(br, vlan, &pid);
                    pid++;

                    snprintf(expr, sizeof(expr), "brctl addif %s %s", br->name, vlan->name);
                    if (execute_cmd(expr) < 0) {
                        goto err_out;
                    }

                    vlan->connect(vlan, eth, &vid);
                }
            }
        }
    }
    
err_out:      
    if (context) {
        xmlXPathFreeContext(context);
    }

    if (doc) {
        xmlFreeDoc(doc);
    }

    return;
}

void fastpath_cleanup_stack(void)
{
    int i;
    const char *str;
    char expr[256];
    xmlDocPtr   doc = NULL; 
    xmlNodePtr  node;
    xmlXPathObjectPtr nodeset;
    xmlXPathContextPtr context = NULL;

    fastpath_log_info("stack cleanup start\n");

    doc = xmlReadFile(FASTPATH_STACK_CONFIG, NULL, XML_PARSE_NOBLANKS);
    if (doc == NULL) {
        fastpath_log_error("stack_cleanup: read config file failed\n");
        goto err_out;
    }
    
    if (xmlDocGetRootElement(doc) == NULL) {
        fastpath_log_error("stack_cleanup: get root element\n");
        goto err_out;
    }
    
    context = xmlXPathNewContext(doc);
    if (context == NULL) {
        fastpath_log_error("stack_cleanup: get context failed\n");
        goto err_out;
    }

    /* bridge */
    nodeset = xml_get_nodeset(context, "//bridge-list/bridge");
    if (nodeset == NULL) {
        fastpath_log_error("get bridge failed\n");
        goto err_out;
    }
    for (i = 0; i < nodeset->nodesetval->nodeNr; i++) {
        uint16_t pid, vid;
        xmlNodePtr member;
        
        node = nodeset->nodesetval->nodeTab[i];
        str = xml_get_param(node, "name", NULL);

        snprintf(expr, sizeof(expr), "ifconfig %s down", str);
        if (execute_cmd(expr) < 0) {
            goto err_out;
        }
        
        snprintf(expr, sizeof(expr), "brctl delbr %s", str);
        if (execute_cmd(expr) < 0) {
            goto err_out;
        }

        str = xml_get_param(node, "vlan", NULL);
        vid = strtoul(str, NULL, 0);

        for (member = node->children; member; member = member->next) {
            if (!strcmp((const char *)member->name, "port")) {
                pid = strtoul((const char *)&member->children->content[4], NULL, 0);

                snprintf(expr, sizeof(expr), "//port-list/ethernet[name='%s']/native", 
                    member->children->content);
                node = xml_get_node(context, expr, NULL);
                if (strtoul((const char *)node->children->content, NULL, 0) == vid) {
                    continue;
                }
                
                snprintf(expr, sizeof(expr), "%s.%d", member->children->content, vid);
                if (module_find(expr) == NULL) {
                    snprintf(expr, sizeof(expr), "ifconfig %s down", member->children->content);
                    if (execute_cmd(expr) < 0) {
                        goto err_out;
                    }
                    
                    snprintf(expr, sizeof(expr), "vconfig rem %s.%d", member->children->content, vid);
                    if (execute_cmd(expr) < 0) {
                        goto err_out;
                    }
                }
            }
        }
    }
    
err_out:      
    if (context) {
        xmlXPathFreeContext(context);
    }

    if (doc) {
        xmlFreeDoc(doc);
    }

    return;
}

