#include "untrusted_header.h"

#define PATH_MAX 1024


static void get_random_bytes(void *buf, int nbytes)
{
    unsigned char * cp = (unsigned char *)buf;
    int             i  = 0;

    srand(time(NULL));

    for (cp = buf, i = 0; i < nbytes; i++) {
        *cp++ ^= (rand() >> 7) & 0xFF;
    }
}

static int
create_enclave(const char * enclave_path)
{
    sgx_launch_token_t launch_token        = { 0 };
    int                launch_token_update = 0;

    int ret = sgx_create_enclave(enclave_path,
                                 SGX_DEBUG_FLAG,
                                 &launch_token,
                                 &launch_token_update,
                                 &global_enclave_id,
                                 NULL);

    if (ret != SGX_SUCCESS) {
        log_error("Error, call sgx_create_enclave fail. ret=%x\n", ret);
        return -1;
    }

    return 0;
}



static void
usage();

static int
initialization(int argc, char ** argv)
{
    struct rk_initial * instance    = NULL;

    char              * owner_fpath = NULL;

    if (argc < 1) {
        log_error("not enough arguments\n");
        usage();
        return -1;
    }


    instance = create_rk_instance();

    if (instance == NULL) {
        log_error("could not create instance\n");
        return -1;
    }


    owner_fpath = strndup(argv[1], PATH_MAX);

    if (store_init_message(owner_fpath, instance)) {
        log_error("could not serialize key file\n");
        goto err;
    }


    log_info("Created instance at: %s", owner_fpath);

    free_init_message(instance);

    nexus_free(owner_fpath);

    return 0;

err:
    nexus_free(owner_fpath);
    free_init_message(instance);

    return -1;
}

static int
exchange(int argc, char ** argv)
{
    struct rk_initial * owner_instance    = NULL;
    struct rk_initial * other_instance    = NULL;

    if (argc < 3) {
        log_error("not enough arguments\n");
        usage();
        return -1;
    }

    char * owner_fpath  = strndup(argv[1], PATH_MAX);
    char * other_fpath  = strndup(argv[2], PATH_MAX);
    char * secret_fpath = strndup(argv[3], PATH_MAX);

    owner_instance = fetch_init_message(owner_fpath);

    if (owner_instance == NULL) {
        log_error("could not load: %s\n", owner_fpath);
        goto err;
    }

    other_instance = fetch_init_message(other_fpath);

    if (other_instance == NULL) {
        log_error("could not load: %s\n", other_fpath);
        goto err;
    }


    if (mount_rk_instance(owner_instance)) {
        log_error("mount_rk_instance() FAILED\n");
        goto err;
    }

    if (validate_quote(other_instance->quote, other_instance->quote_size)) {
        log_error("validate_quote() FAILED\n");
        goto err;
    }


    {
        char   secret[8]         = { 0 };
        size_t secret_len         = sizeof(secret);

        char * raw_secret_str     = NULL;
        char * wrapped_secret_str = NULL;

        int ret = -1;


        get_random_bytes(secret, secret_len);


        struct rk_exchange * xchg_message = create_rk_exchange(other_instance, secret, secret_len);

        if (xchg_message == NULL) {
            log_error("create_rk_exchange FAILED\n");
            goto err;
        }


        raw_secret_str = nexus_alt64_encode(secret, secret_len);
        wrapped_secret_str = nexus_alt64_encode(xchg_message->ciphertext, xchg_message->ciphertext_len);

        log_info("xchange: `%s` -> `%s`", raw_secret_str, wrapped_secret_str);

        nexus_free(raw_secret_str);
        nexus_free(wrapped_secret_str);


        ret = store_xchg_message(secret_fpath, xchg_message);

        free_xchg_message(xchg_message);

        if (ret) {
            log_error("could not store xchg message: %s", secret_fpath);
            goto err;
        }
    }


    nexus_free(owner_fpath);
    nexus_free(other_fpath);

    free_init_message(owner_instance);
    free_init_message(other_instance);

    return 0;

err:
    if (owner_fpath) {
        nexus_free(owner_fpath);
    }

    if (other_fpath) {
        nexus_free(other_fpath);
    }

    if (owner_instance) {
        free_init_message(owner_instance);
    }

    if (other_instance) {
        free_init_message(other_instance);
    }

    return -1;
}

static int
extraction(int argc, char ** argv)
{
    struct rk_initial  * owner_instance = NULL;
    struct rk_exchange * xchg_message   = NULL;

    if (argc < 2) {
        log_error("not enough arguments\n");
        usage();
        return -1;
    }

    char * owner_fpath  = strndup(argv[1], PATH_MAX);
    char * secret_fpath = strndup(argv[2], PATH_MAX);

    owner_instance = fetch_init_message(owner_fpath);

    if (owner_instance == NULL) {
        log_error("could not load: %s\n", owner_fpath);
        goto err;
    }


    if (mount_rk_instance(owner_instance)) {
        log_error("mount_rk_instance() FAILED\n");
        goto err;
    }


    xchg_message = fetch_xchg_message(secret_fpath);

    if (xchg_message == NULL) {
        log_error("could not read xchg secret\n");
        goto err;
    }


    {
        uint8_t * secret             = NULL;
        int       secret_len         = 0;

        char *    raw_secret_str     = NULL;
        char *    wrapped_secret_str = NULL;


        secret = extract_rk_secret(xchg_message, &secret_len);

        if (secret == NULL) {
            log_error("could not store xchg message: %s", secret_fpath);
            goto err;
        }


        raw_secret_str = nexus_alt64_encode(secret, secret_len);
        wrapped_secret_str = nexus_alt64_encode(xchg_message->ciphertext, xchg_message->ciphertext_len);

        log_info("extract: `%s` -> `%s`", wrapped_secret_str, raw_secret_str);

        nexus_free(raw_secret_str);
        nexus_free(wrapped_secret_str);
    }


    nexus_free(owner_fpath);
    nexus_free(secret_fpath);

    free_xchg_message(xchg_message);
    free_init_message(owner_instance);

    return 0;

err:
    if (owner_fpath) {
        nexus_free(owner_fpath);
    }

    if (secret_fpath) {
        nexus_free(secret_fpath);
    }

    if (owner_instance) {
        free_init_message(owner_instance);
    }

    if (xchg_message) {
        free_xchg_message(xchg_message);
    }

    return -1;
}




struct _cmd {
    char * name;
    int (*handler)(int argc, char ** argv);
    char * desc;
    char * usage;
};

static struct _cmd cmds[]
    = { { "init", initialization, "Initialize an instance", "owner_fpath" },
        { "exchange", exchange, "Generate secret and seal", "owner_fpath other_fpath secret_fpath" },
        { "extract", extraction, "Extracts wrapped secret", "owner_fpath secret_fpath" },
        { 0, 0, 0 } };

static void
usage(char * prog)
{
    int i = 0;

    printf("Usage: %s <command> [args...]\n", prog);
    printf("Commands:\n");

    while (cmds[i].name) {
        printf("%-5s -- %s\n", cmds[i].name, cmds[i].desc);
        printf("\t%s %s %s\n", prog, cmds[i].name, cmds[i].usage);
        i++;
    }
}


int
main(int argc, char ** argv)
{
    int ret = -1;
    int i   = 0;


    if (create_enclave(ENCLAVE_PATH)) {
        log_error("could not create the enclave (%s)\n", ENCLAVE_PATH);
        return -1;
    }

    log_info("Created enclave (%s)", ENCLAVE_PATH);

    if (argc < 2) {
        usage(argv[0]);
        exit(-1);
    }

    while (cmds[i].name) {

        if (strncmp(cmds[i].name, argv[1], strlen(argv[1])) == 0) {
            ret = cmds[i].handler(argc - 1, &argv[1]);

            exit(ret);
        }

        i++;
    }

#if 0
    {
        struct rk_initial * rk_instance = create_rk_instance();

        if (rk_instance == NULL) {
            log_error("could not create instance\n");
            return -1;
        }

        if (serialize_keypair_file(global_owner_filepath, rk_instance)) {
            free_rk_instance(rk_instance);
            log_error("could not serialize key file\n");
            return -1;
        }

        free_rk_instance(rk_instance);
        log_info("Created instance at: %s\n", global_owner_filepath);
    }

    {
        struct rk_initial * rk_instance = parse_keypair_file(global_owner_filepath);

        if (rk_instance == NULL) {
            log_error("could not read keypair: %s\n", global_owner_filepath);
            return -1;
        }

        if (mount_rk_instance(rk_instance)) {
            free_rk_instance(rk_instance);

            log_error("could not create instance\n");
            return -1;
        }

        free_rk_instance(rk_instance);
        log_info("Mounted instance at: %s\n", global_owner_filepath);
    }

    struct rk_initial * rk_instance1 = create_rk_instance();
    struct rk_initial * rk_instance2 = create_rk_instance();

    struct public_key pk_ephemeral = { 0 };

    struct nonce nonce;

    char * secret             = "hehe";
    char * wrapped_secret_str = NULL;


    {
        int err = -1;
        int ret = -1;


        if (mount_rk_instance(rk_instance1)) {
            free_init_message(rk_instance1);

            log_error("mounting instance failed\n");
            return -1;
        }
    }

    wrapped_secret_str = nexus_alt64_encode(wrapped_secret, wrapped_secret_len);
    log_info("wrapped_secret: `%s` -> `%s`\n", secret, wrapped_secret_str);

    {

        if (mount_rk_instance(rk_instance2)) {
            free_rk_instance(rk_instance2);

            log_error("mounting instance failed\n");
            return -1;
        }
    }

    log_info("unwrapped_data: `%s` -> `%s`\n", wrapped_secret_str, (char *)unwrapped_secret);
#endif

    return 0;
}
