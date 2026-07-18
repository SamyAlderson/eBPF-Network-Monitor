#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/errqueue.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <libelf.h>
#include <bpf/libbpf.h>

#define MAX_DEV_NAME 1024
#define MAX_ADDR_STR 256
#define MAX_BPF_MAP_NAME 256

// Define user-space BPF map type
typedef enum {
    NETHOOK_MAP_TYPE_PACKET,
    NETHOOK_MAP_TYPE_METRICS,
    NETHOOK_MAP_TYPE_ERRQUEUE
} nethook_map_type_t;

// Define user-space BPF map structure
typedef struct {
    char name[MAX_BPF_MAP_NAME];
    nethook_map_type_t type;
} nethook_map_t;

// Define BPF program handle
typedef struct bpf_program bpf_program_handle;

// Function prototypes
void usage(char *prog);
int load_bpf_program(const char *file_path);
int attach_bpf_program(int dev_idx);
int detach_bpf_program(int dev_idx);
int get_bpf_map_info(const char *map_name, nethook_map_t *map);
int get_bpf_map_value(const char *map_name, nethook_map_t *map);
int print_bpf_map_value(const char *map_name, nethook_map_t *map);

int main(int argc, char **argv) {
    char dev_name[MAX_DEV_NAME];
    bpf_program_handle *prog;
    nethook_map_t map;

    // Parse command-line arguments
    if (argc != 3) {
        usage(argv[0]);
        return -1;
    }

    // Load BPF program
    prog = load_bpf_program(argv[1]);
    if (!prog) {
        fprintf(stderr, "Failed to load BPF program\n");
        return -1;
    }

    // Attach BPF program to device
    int dev_idx = attach_bpf_program(prog);
    if (dev_idx < 0) {
        fprintf(stderr, "Failed to attach BPF program to device\n");
        return -1;
    }

    // Get BPF map info
    strcpy(map.name, argv[2]);
    nethook_map_type_t map_type = get_bpf_map_info(map.name, &map);
    if (map_type < 0) {
        fprintf(stderr, "Failed to get BPF map info\n");
        return -1;
    }

    // Get and print BPF map value
    int value = get_bpf_map_value(map.name, &map);
    if (value < 0) {
        fprintf(stderr, "Failed to get BPF map value\n");
        return -1;
    }

    printf("BPF map value: %d\n", value);

    // Detach and unload BPF program
    detach_bpf_program(dev_idx);
    unload_bpf_program(prog);

    return 0;
}

void usage(char *prog) {
    printf("Usage: %s <bpf_program_file> <bpf_map_name>\n", prog);
}

int load_bpf_program(const char *file_path) {
    int fd;
    Elf *elf;

    // Open BPF program file
    fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        perror("failed to open BPF program file");
        return -1;
    }

    // Load BPF program
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        perror("failed to load BPF program");
        close(fd);
        return -1;
    }

    bpf_program_handle *prog = bpf_program_load(elf, BPF_PROG_TYPE_XDP);
    elf_end(elf);
    close(fd);

    return prog;
}

int attach_bpf_program(int dev_idx) {
    int err;
    bpf_program_handle *prog;

    // Attach BPF program to device
    err = bpf_set_link_xdp_fd(dev_idx, prog->fd, 0, BPF_F_XDP_FLAGS_NONE);
    if (err < 0) {
        perror("failed to attach BPF program to device");
        return err;
    }

    return dev_idx;
}

int detach_bpf_program(int dev_idx) {
    int err;

    // Detach BPF program from device
    err = bpf_set_link_xdp_fd(dev_idx, -1, 0, BPF_F_XDP_FLAGS_NONE);
    if (err < 0) {
        perror("failed to detach BPF program from device");
        return err;
    }

    return dev_idx;
}

int get_bpf_map_info(const char *map_name, nethook_map_t *map) {
    int err;
    Elf *elf;

    // Open BPF program file
    int fd = open(map_name, O_RDONLY);
    if (fd < 0) {
        perror("failed to open BPF program file");
        return -1;
    }

    // Load BPF program
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        perror("failed to load BPF program");
        close(fd);
        return -1;
    }

    // Get BPF map info
    err = bpf_map_get_info_by_fd(elf, map_name);
    if (err < 0) {
        perror("failed to get BPF map info");
        elf_end(elf);
        close(fd);
        return -1;
    }

    // Populate nethook_map_t structure
    strcpy(map->name, map_name);

    elf_end(elf);
    close(fd);

    return nethook_map_type_t(map->type);
}

int get_bpf_map_value(const char *map_name, nethook_map_t *map) {
    int err;
    Elf *elf;

    // Open BPF program file
    int fd = open(map_name, O_RDONLY);
    if (fd < 0) {
        perror("failed to open BPF program file");
        return -1;
    }

    // Load BPF program
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        perror("failed to load BPF program");
        close(fd);
        return -1;
    }

    // Get BPF map value
    err = bpf_map_get_value_by_fd(elf, map_name);
    if (err < 0) {
        perror("failed to get BPF map value");
        elf_end(elf);
        close(fd);
        return -1;
    }

    elf_end(elf);
    close(fd);

    return err;
}

int print_bpf_map_value(const char *map_name, nethook_map_t *map) {
    int err;

    // Get BPF map value
    err = get_bpf_map_value(map_name, map);
    if (err < 0) {
        return err;
    }

    printf("BPF map value: %d\n", err);

    return err;
}