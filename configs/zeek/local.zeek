@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/ftp
@load base/protocols/smtp
@load base/files/hash

# Framework scripts for logging and notice handling
@load policy/frameworks/software
@load policy/frameworks/notice
@load policy/frameworks/intel
@load policy/frameworks/files/hash-all-files

# Load tuning scripts first to avoid performance issues
@load ./scripts/tuning/capture-loss.zeek
@load ./scripts/tuning/notice-policy.zeek

# Load our custom detection and enrichment scripts
@load ./scripts/detection/hunt-iocs.zeek
@load ./scripts/detection/weird-scan.zeek
@load ./scripts/enrichment/add-geodata.zeek

# Load local intelligence data (IOCs) - Keep this last
@load ./site/local-intel.zeek

# Redefine the logging directory to match our Docker volume
redef Log::default_rotation_dir = "/var/log/nsm/zeek";

# Configure the Intel Framework to be more sensitive
redef Intel::read_files += {
    "/etc/nsm-rules/zeek-iocs.dat"  # We will create this file from our rules/iocs.txt
};

# Enable file hashing for specific MIME types - great for hunting
redef FTP::default_capture_password = T;
redef HTTP::default_capture_password = T;
redef SSL::default_capture_password = T;