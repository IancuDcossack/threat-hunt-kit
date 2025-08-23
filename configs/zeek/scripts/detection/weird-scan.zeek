# Weird Scan Detection
# This script generates notices for potential horizontal/vertical scans.

event connection_established(c: connection)
    {
    # Check for connections to many different ports (potential vertical scan)
    if ( c$id$resp_h in Site::local_nets &&
         c$history == "S" &&
         |c$id$resp_p| > 1 )
        {
        NOTICE([$note=Scan::PortScan,
                $conn=c,
                $identifier=cat(c$id$orig_h),
                $msg=fmt("Possible vertical scan from %s", c$id$orig_h)]);
        }
    }