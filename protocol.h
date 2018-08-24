#pragma once



struct rk_initial *
create_rk_instance();

int
mount_rk_instance(struct rk_initial * rk_instance);

struct rk_exchange *
create_rk_exchange(struct rk_initial * other_instance, uint8_t * data, size_t len);

uint8_t *
extract_rk_secret(struct rk_exchange * message, int * len);


