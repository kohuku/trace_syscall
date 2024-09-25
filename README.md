# TRACE_SYACALL

# HOW TO BUILD

## INSTALL PACAGE
```
sudo apt update
sudo apt install clang llvm make gcc libelf-dev pkg-config
```

## BUILD bpftool
[bpf-tool](https://github.com/libbpf/bpftool)


# HOW TO USE
```
sudo ./pamspy -p $(/usr/sbin/ldconfig -p | grep libpam.so | cut -d ' ' -f4)
```
