import sys
from elftools.elf.elffile import ELFFile
from typing import Union

def elfsize(path: str) -> Union[int, None]:
    """
    Calculate the size of an ELF file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        int: The calculated size of the ELF file.
        None: If there was an error reading or parsing the file.
    """
    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            
            # Get the section header offset, entry size, and number of sections
            e_shoff = elf.header['e_shoff']
            e_shentsize = elf.header['e_shentsize']
            e_shnum = elf.header['e_shnum']
            
            # Calculate the end of the section header table
            section_header_table_end = e_shoff + (e_shentsize * e_shnum)

            # Get the last section's end (using its offset and size)
            last_section = elf.get_section(elf.num_sections() - 1)
            last_section_end = last_section['sh_offset'] + last_section['sh_size']

            # Get the last program header's end (using its offset and file size)
            last_segment = elf.get_segment(elf.num_segments() - 1)
            last_segment_end = last_segment['p_offset'] + last_segment['p_filesz']

            # Return the maximum of the section header table, last section, and last segment ends
            return max(section_header_table_end, last_section_end, last_segment_end)
    except Exception as e:
        print(f"Error reading or parsing ELF file: {e}")
        return None

if __name__ == "__main__":
    path = sys.argv[1]
    size = elfsize(path)
    if size:
        print(f"Size of {path}: {size} bytes")
    else:
        print(f"Failed to calculate size of {path}")
