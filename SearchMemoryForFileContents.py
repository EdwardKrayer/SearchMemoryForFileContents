# Search for file contents
# @author Edward Krayer
# @category Search
# @keybinding
# @menupath
# @toolbar
# @runtime Jython

# Clear matching range of existing code.
opt__clear_range = True

# Bookmark Options:         {0} = Address
#                           {1} = File Name
#                           {2} = Instance Count
opt__create_bookmark = True
opt__format_bookmark_note = "{1} #{2}"
opt__format_bookmark_category = "FindFileContents"

# Label Options:            {0} = Address
#                           {1} = File Name
#                           {2} = Instance Count
opt__create_label = True
opt__format_label = "file_{1}{2}_{0}"
opt__make_label_primary = True
opt__clear_preexisting_labels = True

opt__create_data_type = True

import sys
import os.path

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.data import ByteDataType, ArrayDataType
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.label import DeleteLabelCmd

from docking.widgets.filechooser import GhidraFileChooser, GhidraFileChooserMode

ghidra_api = FlatProgramAPI(currentProgram)

def find_bytes_in_memory(find_bytes, min_addr=None):
    """
    Find bytes in the memory of the current program starting from a specified address.
    
    :param find_bytes: The byte sequence to find.
    :param min_addr: The minimum address to start the search from (default is the program's minimum address).
    :return: The address where the byte sequence is found or None if not found.
    """
    min_addr = min_addr or currentProgram.getMinAddress()
    return currentProgram.getMemory().findBytes(min_addr, find_bytes, None, True, monitor)


def create_label_at_address(addr, label_name, source=SourceType.USER_DEFINED):
    """
    Create a label at a specified memory address.
    
    :param addr: The target memory address.
    :param label_name: The name of the label to be created.
    :param source: The source type of the label (default is USER_DEFINED).
    """
    symbol_table = currentProgram.getSymbolTable()
    symbol_table.createLabel(addr, label_name, source)

def apply_data_type_to_memory(addr, data_type, n=1):
    """
    Apply a data type or an array of data types at a specific memory address.
    
    :param addr: The target memory address.
    :param data_type: The data type to be applied.
    :param n: The number of elements, if an array (default is 1).
    """
    
    if n > 1:
        data_type = ArrayDataType(data_type, n)
    
    try:
        ghidra_api.createData(addr, data_type)
        print("Defined an array of size {0} at address {1}".format(n, addr))
    except MemoryAccessException as e:
        print("Failed to define data type at address {0}: {1}".format(addr, e))
    except Exception as e:
        print("An unexpected error occurred at address {0}: {1}".format(addr, e))

def show_dialog(base_directory = None):
    """
    Display a file chooser dialog to select files and directories.
    
    :param base_directory: The initial directory to open in the file chooser. If None, 
                           defaults to the program's file directory.
    :return: The selected files or directories.
    """
    base_directory = base_directory or ghidra_api.getProgramFile()
    file_chooser = GhidraFileChooser(None)
    file_chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES)
    file_chooser.setCurrentDirectory(base_directory)
    file_chooser.setMultiSelectionEnabled(True)
    file_chooser.setApproveButtonToolTipText('Choose source file / directory.')
    file_chooser.setTitle('Select Files / Directories')
    
    selected_files = file_chooser.getSelectedFiles()

    if selected_files is None:
        sys.exit(1)
    else:
        return selected_files

def get_files_recursively(paths):
    """
    Given a list of paths, return a list of all files. If a path is a directory,
    all files within that directory and its subdirectories will be included.
    
    :param paths: List of file and directory paths.
    :return: List of all files found in the given paths.
    """
    all_files = []
    
    for path in map(str, paths):
        if os.path.isfile(path):
            all_files.append(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                all_files.extend(os.path.join(root, file) for file in files)
    
    return all_files


def read_file_to_bytes(file_path, chunk_size=4096):
    """
    Read the contents of a file into a bytes object, reading in chunks.
    
    :param file_path: The path to the file to be read.
    :param chunk_size: The size of each chunk to read (default is 4096 bytes).
    :return: A bytes object containing the file data, or None if an error occurs.
    """
    try:
        file_data = bytearray()
        with open(str(file_path), 'rb') as file:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                file_data.extend(chunk)
        return bytes(file_data)
    except IOError as e:
        print('An error occurred while reading the file:', e)
        return None

def seek_data_from_array(data, min_addr=None):
    """
    Search for a byte sequence in memory and return a list of addresses where the sequence is found.
    
    :param data: The byte sequence to search for.
    :param min_addr: The minimum address to start the search from (default is None, meaning search from the beginning).
    :return: A list of addresses where the byte sequence is found.
    """
    results = []
    search_result = ghidra_api.find(min_addr, data)
    
    while search_result is not None:
        results.append(search_result)
        min_addr = search_result.next()
        search_result = find_bytes_in_memory(data, min_addr)

    return results

def find_code_between_addresses(start, end):
    """
    Check if code exists in an address range.
    
    :param start: Start of range.
    :param end: End of range.
    :return: (bool)
    """
    i = start
    while (i <= end):
        if currentProgram.getListing().getCodeUnitAt(i):
            return True
        i.next()
    return

userSelection = show_dialog()
try:
    paths = get_files_recursively(userSelection)

    for file in paths:

        instanceCount = 0
        fileName = os.path.basename(file)
        fileData = read_file_to_bytes(file)
        fileSize = len(fileData)

        print("{0:<48.44}{1:>16}".format(
                    fileName,
                    "Searching"
                )
            )

        positions = seek_data_from_array(fileData, None)

        for instanceCount, position in enumerate(positions):

            position_end = position.add(fileSize)

            print("{0:<48.44}{4:>16}\t@ {2} -> {3}".format(
                        fileName,
                        instanceCount,
                        position,
                        position_end,
                        'Found #' + str(instanceCount)
                    )
                )

            if opt__clear_range:
                if find_code_between_addresses(position, position_end):
                    print("{0:<48.44}{1:>16}\t@ {2} -> {3}"
                            .format(
                                    fileName,
                                    "Clearing Code",
                                    position,
                                    position_end
                                )
                        )
                ghidra_api.clearListing(
                        position,
                        position_end
                    )
                
            if opt__clear_preexisting_labels:
                while True:
                    current_label = currentProgram.getListing().getCodeUnitAt(
                            position
                        ).getLabel()
                    if current_label:
                        print("{0:<48.44}{2:>16}\t{1}"
                                .format(
                                        fileName,
                                        "\"" + str(current_label) + "\"",
                                        "Deleting Label"        
                                    )
                            )
                        DeleteLabelCmd(
                                position,
                                str(current_label)
                            ).applyTo(currentProgram)
                    else:
                        break

            if opt__create_label:
                new_label = opt__format_label.format(
                        position,
                        fileName,
                        instanceCount
                    )
                
                ghidra_api.createLabel(
                        position,
                        opt__format_label.format(
                                position,
                                fileName,
                                instanceCount
                            ),
                        opt__make_label_primary,
                        SourceType.USER_DEFINED
                    )
                
                print("{0:<48.44}{1:>16}\t{2}"
                        .format(
                                fileName,
                                "Added Label",
                                "\"" + new_label + "\""
                            )
                    )

            if opt__create_bookmark:
                ghidra_api.createBookmark(
                        position,
                        opt__format_bookmark_category,
                        opt__format_bookmark_note.format(
                                position,
                                fileName,
                                instanceCount
                            )
                    )

            if opt__create_data_type:
                ghidra_api.createData(
                        position,
                        ArrayDataType(
                                ByteDataType.dataType,
                                fileSize
                            )
                    )
            
            instanceCount += 1
except Exception as e:
    print('An error occurred:', e)
    sys.exit(1)
