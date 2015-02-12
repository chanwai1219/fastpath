
#include "fastpath.h"

#define FASTPATH_STACK_CONFIG   "./stack.cfg"

struct module_entry {
    struct module *module;
    LIST_ENTRY(module_entry) entry;
};

LIST_HEAD(, module) module_list;

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

void module_add(struct module *module)
{
    struct module_entry *entry;

    if (module == NULL) {
        fastpath_log_error("module_add: invalid module\n");
        return;
    }

    entry = rte_malloc(NULL, sizeof(module_entry), 0);
    if (entry == NULL) {
        fastpath_log_error("module_add: malloc failed\n");
        return;
    }

    entry->module = module;

    LIST_INSERT_HEAD(&module_list, module, entry);
}

void module_print()
{
    struct module *module;
    struct module_entry *entry;
    
    LIST_FOREACH(
}

void stack_setup(void)
{
    int i;
    char *str;
    struct module *module;
    struct module_entry *entry;
    xmlDocPtr   doc = NULL; 
    xmlNodePtr  node;
    xmlXPathObjectPtr nodeset;
    xmlXPathContextPtr context = NULL;

    doc = xmlReadFile(FASTPATH_STACK_CONFIG, NULL, XML_PARSE_NOBLANKS);
    if (doc == NULL) {
        fastpath_log_error("%s: read %s failed\n", __func__, DP_RUN_CFG);
        goto err_out;
    }
    
    if (xmlDocGetRootElement(doc) == NULL) {
        fastpath_log_error(LOG_ERR, "%s: get root element\n", __func__);
        goto err_out;
    }
    
    context = xmlXPathNewContext(doc);
    if (context == NULL) {
        fastpath_log_error(LOG_ERR, "%s: get context failed\n", __func__);
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
        } else (strcmp(str, "access") == 0) {
            mode = VLAN_MODE_ACCESS;
        }
        str = xml_get_param(node, "native", NULL);
        native = strtoul(str, NULL, 0);
        
        module = ethernet_init(port, mode, native);
        module_add(module);
    }

    /* bridge */
    nodeset = xml_get_nodeset(context, "//bridge-list/bridge");
    if (nodeset == NULL) {
        fastpath_log_error("get bridge failed\n");
        goto err_out;
    }
    for (i = 0; i < nodeset->nodesetval->nodeNr; i++) {
        uint16_t vid;
        
        node = nodeset->nodesetval->nodeTab[i];

        str = xml_get_param(node, "vlan", NULL);
        vid = strtoul(str, NULL, 0);

        module = bridge_init(vid);
        module_add(module);
    }

    /* interface */
    nodeset = xml_get_nodeset(context, "//interface-list/interface");
    if (nodeset == NULL) {
        fastpath_log_error("get interface failed\n");
        goto err_out;
    }
    for (i = 0; i < nodeset->nodesetval->nodeNr; i++) {
        uint32_t ifidx;
        
        node = nodeset->nodesetval->nodeTab[i];

        str = xml_get_param(node, "name", NULL);
        ifidx = strtoul(&str[3], NULL, 0);

        module = interface_init(ifidx);
        module_add(module);
    }

    /* ip forward */
    module = ipfwd_init();
    module_add(module);
    
    LIST_FOREACH(

err_out:      
    if (context) {
        xmlXPathFreeContext(context);
    }

    if (doc) {
        xmlFreeDoc(doc);
    }

    return;


    fastpath_log_info("%s %d\n", __func__, __LINE__);

    for (port = 0; port < FASTPATH_MAX_NIC_PORTS; port ++) {
        uint32_t n_rx_queues = fastpath_get_nic_rx_queues_per_port((uint8_t) port);

        if (n_rx_queues == 0) {
            continue;
        }

        eth[port] = ethernet_init(port, VLAN_MODE_TRUNK, 1);
    }

    br = bridge_init(1);
    for (port = 0; port < FASTPATH_MAX_NIC_PORTS; port ++) {
        if (eth[port] != NULL) {
            br->connect(br, eth[port], (void *)&port);
        }
    }
    
}

