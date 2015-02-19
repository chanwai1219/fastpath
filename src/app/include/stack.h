
#ifndef __STACK_H__
#define __STACK_H__

xmlNodePtr xml_get_child(xmlNodePtr node, const char *name);
const char * xml_get_param(xmlNodePtr node, const char *name, const char* def_val);
xmlXPathObjectPtr xml_get_nodeset(xmlXPathContextPtr context, const char *path);
xmlNodePtr xml_get_node(xmlXPathContextPtr context, const char *path, int *dup);

struct module *module_get_by_name(const char *name);

void fastpath_init_stack(void);

#endif

