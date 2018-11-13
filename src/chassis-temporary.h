#ifndef __CHASSIS_TEMPORARY_H__
#define __CHASSIS_TEMPORARY_H__

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include "cJSON.h"
#include "chassis-mainloop.h"

typedef enum {
    CONFIG_TYPE,
    USERS_TYPE,
    VARIABLES_TYPE,
    VDB_TYPE,
    TABLES_TYPE,
    SINGLE_TABLES_TYPE
}config_type_t;
//config
gboolean load_config_from_temporary_file(chassis *chas);
gboolean config_set_local_options_by_key(chassis *chas, gchar *key); 
#endif
