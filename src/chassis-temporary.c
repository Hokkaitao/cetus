#include "chassis-temporary.h"
#include "sharding-config.h"
#include "chassis-plugin.h"
#include "chassis-options-utils.h"
#include "cetus-users.h"
#include "sql-filter-variables.h"

static gboolean
rm_config_json_local(gchar *filename) {
    if(!filename) return FALSE;
    if(g_file_test(filename, G_FILE_TEST_EXISTS)) {
        gint ret = g_unlink(filename);
        if(ret == 0) {
            return TRUE;
        } else {
            g_critical(G_STRLOC "unlink file: %s failed", filename);
            return FALSE;
        }
    }
    return TRUE;
}

static gboolean
read_config_json_from_local(gchar *filename, gchar **str) {
    if(!filename) return FALSE;
    gchar *buffer = NULL;
    GError *err = NULL;
    if (!g_file_get_contents(filename, &buffer, NULL, &err)) {
        if (!g_error_matches(err, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
            g_critical(G_STRLOC "read config file failed:  %s", err->message);
        }
        g_clear_error(&err);
        return FALSE;
    }
    if(buffer && strlen(buffer) == 0) {
        g_free(buffer);
        buffer = NULL;
    }
    *str = buffer;
    return TRUE;
}

static gboolean 
write_config_json_to_local(gchar *filename, gchar *str) {
    if(!filename) return FALSE;
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        g_critical(G_STRLOC "can't open file: %s for write", filename);
        return FALSE;
    }
    if(str) {
        fwrite(str, 1, strlen(str), fp);
    }
    fclose(fp);
    return  TRUE;
}

static gboolean
get_config_from_json_by_type(gchar *json, config_type_t type, gchar **str) {
    if(!json) return TRUE;
    cJSON *root = cJSON_Parse(json);
    cJSON *root_sub = NULL;
    if (!root) {
        g_critical(G_STRLOC ":json syntax error in get_config_from_json_by_type()");
        return FALSE;
    }
    switch(type) {
    case CONFIG_TYPE:{
        cJSON *config = cJSON_GetObjectItem(root, "config");
        if(config) {
            root_sub = cJSON_CreateObject();
            if(!root_sub) {
                g_critical(G_STRLOC ":cJSON_CreateObject failed");
            } else {
                cJSON *config_copy = cJSON_Duplicate(config, 1);
                cJSON_AddItemToObject(root_sub, "config", config_copy);
            }
        }
        break;
    }
    case USERS_TYPE:{
        cJSON *users = cJSON_GetObjectItem(root, "users");
        if(users) {
            root_sub = cJSON_CreateObject();
            if(!root_sub) {
                g_critical(G_STRLOC ":cJSON_CreateObject failed");
            } else {
                cJSON *users_copy = cJSON_Duplicate(users, 1);
                cJSON_AddItemToObject(root_sub, "users", users_copy);
            }
        }
        break;
    }
    case VARIABLES_TYPE:{
        cJSON *variables = cJSON_GetObjectItem(root, "variables");
        if(variables) {
            root_sub = cJSON_CreateObject();
            if(!root_sub) {
                g_critical(G_STRLOC ":cJSON_CreateObject failed");
            } else {
                cJSON *variables_copy = cJSON_Duplicate(variables, 1);
                cJSON_AddItemToObject(root_sub, "variables", variables_copy);
            }
        }
        break;
    }
    case VDB_TYPE:{
        cJSON *vdb = cJSON_GetObjectItem(root, "vdb");
        if(vdb) {
            root_sub = cJSON_CreateObject();
            if(!root_sub) {
                g_critical(G_STRLOC ":cJSON_CreateObject failed");
            } else {
                cJSON *vdb_copy = cJSON_Duplicate(vdb, 1);
                cJSON_AddItemToObject(root_sub, "vdb", vdb_copy);
            }
        }
        break;
    }
    case TABLES_TYPE:{
        cJSON *tables = cJSON_GetObjectItem(root, "table");
        if(tables) {
            root_sub = cJSON_CreateObject();
            if(!root_sub) {
                g_critical(G_STRLOC ":cJSON_CreateObject failed");
            } else {
                cJSON *tables_copy = cJSON_Duplicate(tables, 1);
                cJSON_AddItemToObject(root_sub, "table", tables_copy);
            }
        }
        break;
    }
    case SINGLE_TABLES_TYPE:{
        cJSON * single= cJSON_GetObjectItem(root, "single_tables");
        if(single) {
            root_sub = cJSON_CreateObject();
            if(!root_sub) {
                g_critical(G_STRLOC ":cJSON_CreateObject failed");
            } else {
                cJSON *single_copy = cJSON_Duplicate(single, 1);
                cJSON_AddItemToObject(root_sub, "single_tables", single_copy);
            }
        }
        break;
    }
    default:
        g_critical(G_STRLOC ":type unrecognized in get_config_from_json_by_type()");
        return FALSE;
    }
    if(root_sub) {
        *str = cJSON_Print(root_sub);
        cJSON_Delete(root_sub);
    }
    cJSON_Delete(root);
    return TRUE;
}

static gboolean
parse_config_to_json(chassis *chas, gchar **str) {
    cJSON *config_node = cJSON_CreateArray();
    if(!config_node) {
        g_warning(G_STRLOC ":cJSON_CreateArray failed");
        return FALSE;
    }
    GList* list = chas->options->options;
    if(!list) {
        return FALSE;
    }
    GList *l = NULL;
    for(l = list; l; l = l->next) {
        chassis_option_t *opt = l->data;
        struct external_param param = {0};
        param.chas = chas;
        param.opt_type = SAVE_OPTS_PROPERTY;
        gchar *value = opt->show_hook != NULL? opt->show_hook(&param) : NULL;
        if(value) {
            cJSON *node = cJSON_CreateObject();
            cJSON_AddStringToObject(node, "key", opt->long_name);
            cJSON_AddStringToObject(node, "value", value);
            cJSON_AddItemToArray(config_node, node);
        }
    }
    cJSON *root = cJSON_CreateObject();
    if(!root) {
        g_warning(G_STRLOC ":cJSON_CreateObject failed");
        return FALSE;
    }
    cJSON_AddItemToObject(root, "config", config_node);
    *str = cJSON_Print(root);
    cJSON_Delete(root);
    return TRUE;
}

static gchar*
get_config_value_from_json(const gchar *key, gchar *json) {
    if(!json) {
        g_critical(G_STRLOC ":json content is nil");
        return NULL;
    }
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        g_critical(G_STRLOC ":json syntax error");
        return NULL;
    }
    cJSON *config_node = cJSON_GetObjectItem(root, "config");
    if(!config_node) {
        cJSON_Delete(root);
        return NULL;
    }
    cJSON *key_node = config_node->child;
    if(!key_node) {
        cJSON_Delete(root);
        return NULL;
    }
    for(;key_node; key_node = key_node->next) {
        cJSON *keyjson = cJSON_GetObjectItem(key_node, "key");
        if (!keyjson) {
            g_critical(G_STRLOC ": config error, no key");
            break;
        }
        if(strcasecmp(key, keyjson->valuestring) == 0) {
            cJSON *valuejson = cJSON_GetObjectItem(key_node, "value");
            gchar *value = g_strdup(valuejson->valuestring);
            cJSON_Delete(root);
            return value;
        }
    }
    cJSON_Delete(root);
    return NULL;
}

gboolean
load_config_from_temporary_file(chassis *chas) {
    gchar *json = NULL;
    gboolean ret = read_config_json_from_local(chas->temporary_file, &json);
    if(!ret) {
        return ret;
    }
    if(!json) {
        return TRUE;
    }
    gchar *json_config = NULL;
    ret = get_config_from_json_by_type(json, CONFIG_TYPE, &json_config);
    if(!ret) {
        g_free(json);
        return ret;
    }
    GList* list = chas->options->options;
    GList *l = NULL;
    for(l = list; l; l = l->next) {
        chassis_option_t *opt = l->data;
        gchar* value = get_config_value_from_json(opt->long_name, json_config);
        if(value) {
            gint r = 0;
            struct external_param param = {0};
            param.chas = chas;
            param.opt_type = ASSIGN_OPTS_PROPERTY;
            r = opt->assign_hook != NULL? opt->assign_hook(value, &param) : ASSIGN_NOT_SUPPORT;
            if(r != 0) {
                g_critical(G_STRLOC ": load %s from temporary failed", opt->long_name);
            }
            g_free(value);
        }
    }
    if(json) {
        g_free(json);
    }
    if(json_config) {
        g_free(json_config);
    }
    return TRUE;
}

static gboolean
save_config_to_temporary_file(chassis *chas, gchar *key, gchar *value) {
    gboolean ret = TRUE;
    gchar *json = NULL;
    read_config_json_from_local(chas->temporary_file, &json);
    cJSON *root = NULL;
    if(json) {
        root = cJSON_Parse(json);
        g_free(json);
    } else {
        root = cJSON_CreateObject();
    }
    cJSON *config_node = cJSON_GetObjectItem(root, "config");
    if(!config_node) {
        if(!value) {
            goto exit;
        }
        config_node = cJSON_CreateArray();
        cJSON *node = cJSON_CreateObject();
        cJSON_AddStringToObject(node, "key", key);
        cJSON_AddStringToObject(node, "value", value);
        cJSON_AddItemToObject(root, "config", config_node);
        cJSON_AddItemToArray(config_node, node);
        goto save;
    }
    cJSON *key_node = config_node->child;
    if(!key_node) {
        cJSON_Delete(root);
        return FALSE;
    }
    gint which = 0;
    for(;key_node; key_node = key_node->next) {
        cJSON *keyjson = cJSON_GetObjectItem(key_node, "key");
        if (!keyjson) {
            g_critical(G_STRLOC ": config error, no key");
            break;
        }
        if(strcasecmp(key, keyjson->valuestring) == 0) {
            if(!value) {
                cJSON_DeleteItemFromObject(key_node, "value");
                cJSON_DeleteItemFromObject(key_node, "key");
                cJSON_DeleteItemFromArray(config_node, which);
                goto save;
            }
            cJSON *valuejson = cJSON_GetObjectItem(key_node, "value");
            if(strcasecmp(value, valuejson->valuestring) != 0) {
                cJSON_DeleteItemFromObject(key_node, "value");
                cJSON_AddItemToObject(key_node, "value", cJSON_CreateString(value));
                goto save;
            } else {
                cJSON_Delete(root);
                return TRUE;
            }
        }
        which ++;
    }

    if(!value) {
        goto exit;
    }
    cJSON *node = cJSON_CreateObject();
    cJSON_AddStringToObject(node, "key", key);
    cJSON_AddStringToObject(node, "value", value);
    cJSON_AddItemToArray(config_node, node);

save:
    ret = write_config_json_to_local(chas->temporary_file, cJSON_Print(root));
exit:
    cJSON_Delete(root);
    return ret;
}

gboolean config_set_local_options_by_key(chassis *chas, gchar *key) {
    if(!key) return ASSIGN_ERROR;
    GList *options = g_list_copy(chas->options->options);
    GList *l = NULL;
    for(l = options; l; l = l->next) {
        chassis_option_t *opt = l->data;
        if(strcasecmp(key, opt->long_name) == 0) {
            struct external_param param = {0};
            param.chas = chas;
            param.opt_type = SAVE_OPTS_PROPERTY;
            gchar *value = (opt->show_hook != NULL)? opt->show_hook(&param) : NULL;
            gboolean ret = save_config_to_temporary_file(chas, key, value);
            if(value) {
                g_free(value);
            }
            return ret;
        }
    }
    return FALSE;
}

gboolean sync_config_to_file(chassis *chas, gint *effected_rows) {
    GKeyFile *keyfile = g_key_file_new();
    g_key_file_set_list_separator(keyfile, ',');
    GString *free_path = g_string_new(NULL);
    if(chas->default_file == NULL) {
        free_path = g_string_append(free_path, chas->conf_dir);
        free_path = g_string_append(free_path, "/default.conf");
        chas->default_file = g_strdup(free_path->str);
    }
    if(!g_path_is_absolute(chas->default_file)) {
        gchar * current_dir =  g_get_current_dir();
        free_path = g_string_append(free_path, current_dir);
        free_path = g_string_append(free_path, "/");
        free_path = g_string_append(free_path, chas->default_file);
        g_free(chas->default_file);
        chas->default_file = g_strdup(free_path->str);
        g_free(current_dir);
    }
    if(free_path) {
        g_string_free(free_path, TRUE);
    }
    *effected_rows = chassis_options_save(keyfile, chas->options, chas);
    gsize file_size = 0;
    gchar *file_buf = g_key_file_to_data(keyfile, &file_size, NULL);
    g_key_file_free(keyfile);
    GError *gerr = NULL;
    if (FALSE == g_file_set_contents(chas->default_file, file_buf, file_size, &gerr)) {
        g_clear_error(&gerr);
        return FALSE;
    } else {
        if(chmod(chas->default_file, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)) {
            g_debug("chmod operate failed, filename:%s, errno:%d",
                    (chas->default_file == NULL? "":chas->default_file), errno);
            return FALSE;
        }
    }
    return TRUE;
}

gboolean load_users_from_temporary_file(chassis *chas) {
    gchar *json = NULL;
    if(!read_config_json_from_local(chas->temporary_file, &json)) {
        g_critical(G_STRLOC ": read config json from local failed");
        return FALSE;
    }
    if(!json) {
        return TRUE;
    }
    gchar *json_users = NULL;
    if(!get_config_from_json_by_type(json, USERS_TYPE, &json_users)) {
        g_free(json);
        g_critical(G_STRLOC ": get users from local failed");
        return FALSE;
    }
    g_free(json);
    if(!json_users) {
        return TRUE;
    }
    cetus_users_parse_json(chas->priv->users, json_users);
    g_free(json_users);
    return TRUE;
}   

gboolean save_users_to_temporary_file(chassis *chas) {
    cetus_users_t *users = chas->priv->users;

    cJSON *users_node = cJSON_CreateArray();
    if (!users_node) {
        g_warning(G_STRLOC ":users_node is nil");
        return FALSE;
    }
    GHashTableIter iter;
    char *username = NULL;
    struct pwd_pair_t *pwd = NULL;
    g_hash_table_iter_init(&iter, users->records);
    while (g_hash_table_iter_next(&iter, (gpointer *) & username, (gpointer *) & pwd)) {
        cJSON *node = cJSON_CreateObject();
        cJSON_AddStringToObject(node, "user", username);
        cJSON_AddStringToObject(node, "client_pwd", pwd->client);
        cJSON_AddStringToObject(node, "server_pwd", pwd->server);
        cJSON_AddItemToArray(users_node, node);
    }
    
    gchar *json = NULL;
    if(!read_config_json_from_local(chas->temporary_file, &json)) {
        g_critical(G_STRLOC "read config from temporary file failed");
        cJSON_Delete(users_node);
        return FALSE;
    }
    cJSON *root = NULL;
    if(!json) {
        root = cJSON_CreateObject();
    } else {
        root = cJSON_Parse(json);
        if(!root) {
            g_warning(G_STRLOC ":root is nil");
            g_free(json);
            return FALSE;
        }
        g_free(json);
    }
    cJSON *users_node_old = cJSON_GetObjectItem(root, "users");
    if(users_node_old) {
        cJSON_DeleteItemFromObject(root, "users");
    }
    cJSON_AddItemToObject(root, "users", users_node);
    gboolean r = write_config_json_to_local(chas->temporary_file, cJSON_Print(root));
    cJSON_Delete(root);
    return r;
}

gboolean sync_users_to_file(chassis *chas, gint *effected_rows) {
    gchar *json = NULL;
    if(!read_config_json_from_local(chas->temporary_file, &json)) {
        g_critical(G_STRLOC "read config from temporary file failed");
        return FALSE;
    }
    gchar *json_users = NULL;
    gboolean ret = get_config_from_json_by_type(json, USERS_TYPE, &json_users);
    g_free(json);
    if(!ret) {
        return ret;
    }
    if(!json_users) {
        return TRUE;
    }
    gboolean r = chassis_config_write_object(chas->priv->users->conf_manager, "users", json_users);
    g_free(json_users);
    return r;
}

gboolean save_variables_to_temporary_file(chassis *chas) {
    gchar *json_variables = NULL;
    if(!parse_variables_to_json(&json_variables)) {
        g_critical(G_STRLOC "parse variables to json failed");
        return FALSE;
    }
    if(!json_variables || strlen(json_variables) == 0) {
        if(json_variables) g_free(json_variables);
        return TRUE;
    }
    cJSON *variables_root = cJSON_Parse(json_variables);
    if(!variables_root) {
        g_warning(G_STRLOC ":variables root is nil"); 
        g_free(json_variables);
        return TRUE;
    }
    g_free(json_variables);
    cJSON *variables_node = cJSON_GetObjectItem(variables_root, "variables");
    if(!variables_node) {
        cJSON_Delete(variables_root);
        return TRUE;
    }
    cJSON *variables_node_copy = cJSON_Duplicate(variables_node, 1);
    cJSON_Delete(variables_root);
    gchar *json = NULL;
    if(!read_config_json_from_local(chas->temporary_file, &json)) {
        g_critical(G_STRLOC "read config from temporary file failed");
        g_free(json_variables);
        return FALSE;
    }
    cJSON *root = NULL;
    if(!json) {
        root = cJSON_CreateObject();
    } else {
        root = cJSON_Parse(json);
        g_free(json);
        if(!root) {
            g_warning(G_STRLOC ":root is nil");
            g_free(json);
            return FALSE;
        }
    }
    cJSON *variables_node_old = cJSON_GetObjectItem(root, "variables");
    if(variables_node_old) {
        cJSON_DeleteItemFromObject(root, "variables");
    }
    cJSON_AddItemToObject(root, "variables", variables_node_copy);
    gboolean r = write_config_json_to_local(chas->temporary_file, cJSON_Print(root));
    cJSON_Delete(root);
    return r;
}
