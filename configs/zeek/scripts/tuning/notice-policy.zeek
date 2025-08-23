# Notice Policy Script
# This script tunes which notices are actually written to disk.

# Ignore these very common, often benign notices
redef Notice::ignored_types += {
    SSL::Invalid_Server_Cert,
    SSL::Weak_Key,
    HTTP::Incorrect_File_Version,
};