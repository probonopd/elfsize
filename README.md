# elfsize

Calculate the size of an ELF file on disk. This is useful, e.g., to find out at which offset the filesystem image of an AppImage starts.

## Building

```
gcc -o elfsize elfsize.c
```

## Testing

```
ls -l ./elfsize
# 17136

./elfsize ./elfsize
# 17136

# Append some data after the ELF
echo "appendeddata" >> ./elfsize

# Check whether we still get the correct ELF size
./elfsize ./elfsize
# 17136
```
