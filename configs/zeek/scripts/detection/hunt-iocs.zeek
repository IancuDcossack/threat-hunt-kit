# Custom IOC Hunting Script
# This script uses the Intel Framework to match traffic against IOCs.

# Print a log message when Zeek starts to confirm this script loaded
print "[*] Loading custom IOC hunting script";

# Define what types of data we want to match against which intelligence types
redef Intel::match_types = {
    ["DOMAIN"] = Intel::DOMAIN,
    ["URL"] = Intel::URL,
    ["SOFTWARE"] = Intel::SOFTWARE,
    ["EMAIL"] = Intel::EMAIL,
    ["FILE_HASH"] = Intel::FILE_HASH,
    ["CERT_HASH"] = Intel::CERT_HASH,
};

# We can add a hook to add custom logic when a match is found
hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == Intel::Notice && /malicious/ in n$msg )
        {
        # You could add custom logic here, like sending an alert to a webhook
        # print fmt("HIGH SEVERITY IOC MATCH: %s", n$msg);
        add n$actions[Notice::ACTION_ALARM];
        }
    }