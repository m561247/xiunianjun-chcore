/*
 * Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <malloc.h>
#include <string.h>
#include "fsm_client_cap.h"
#include <errno.h>

struct list_head fsm_client_cap_table;

/* Return mount_id */
int fsm_set_client_cap(badge_t client_badge, cap_t cap)
{
        /* Lab 5 TODO Begin */
        int mount_id = 0;
        struct fsm_client_cap_node *n, *iter_tmp;
        pthread_mutex_lock(&fsm_client_cap_table_lock);

        for_each_in_list_safe (n, iter_tmp, node, &fsm_client_cap_table) {
                if (n->client_badge == client_badge) {
                        for (int i = 0; i < n->cap_num; i ++) {
                                if (n->cap_table[i] == cap) {
                                        mount_id = i;
                                        goto out;
                                }
                        }
                        n->cap_table[n->cap_num] = cap;
                        n->cap_num += 1;
                        mount_id = n->cap_num - 1;
                        goto out;
                }
        }
        n = (struct fsm_client_cap_node *)malloc(sizeof(*n));
        n->cap_table[0] = cap;
        n->cap_num = 1;
        n->client_badge = client_badge;
        list_add(&(n->node), &fsm_client_cap_table);
        
out:
        pthread_mutex_unlock(&fsm_client_cap_table_lock);
        /* Lab 5 TODO End */
        return mount_id;
}

/* Return mount_id if record exists, otherwise -1 */
int fsm_get_client_cap(badge_t client_badge, cap_t cap)
{
        /* Lab 5 TODO Begin */
        struct fsm_client_cap_node *n, *iter_tmp;
        pthread_mutex_lock(&fsm_client_cap_table_lock);

        for_each_in_list_safe (n, iter_tmp, node, &fsm_client_cap_table) {
                if (n->client_badge == client_badge) {
                        for (int i = 0; i < n->cap_num; i ++) {
                                if (n->cap_table[i] == cap) {
                                        pthread_mutex_unlock(&fsm_client_cap_table_lock);
                                        return i;
                                }
                        }
                }
        }

        pthread_mutex_unlock(&fsm_client_cap_table_lock);
        /* Lab 5 TODO End */
        return -1;
}
