# /usr/share/logstash/scripts/zeek_field_mapper.rb
# This script maps Zeek's tab-separated fields to their actual names.

def register(params)
  # Define the field names for each major Zeek log type.
  # These must match the order of fields in the Zeek log header.
  @field_map = {
    "conn" => [
      "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
      "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig",
      "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
      "resp_ip_bytes", "tunnel_parents", "threat"
    ],
    "http" => [
      "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "trans_depth",
      "method", "host", "uri", "referrer", "user_agent", "request_body_len", "response_body_len",
      "status_code", "status_msg", "info_code", "info_msg", "tags", "username", "password",
      "proxied", "orig_fuids", "orig_filenames", "orig_mime_types", "resp_fuids", "resp_filenames",
      "resp_mime_types", "client_header_names", "server_header_names"
    ],
    "dns" => [
      "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
      "trans_id", "rtt", "query", "qclass", "qclass_name", "qtype", "qtype_name",
      "rcode", "rcode_name", "AA", "TC", "RD", "RA", "Z", "answers", "TTLs",
      "rejected"
    ],
    "ssl" => [
      "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "version",
      "cipher", "curve", "server_name", "resumed", "last_alert", "next_protocol",
      "established", "cert_chain_fuids", "client_cert_chain_fuids", "subject", "issuer",
      "client_subject", "client_issuer", "validation_status"
    ],
    "files" => [
      "ts", "fuid", "tx_hosts", "rx_hosts", "conn_uids", "source", "depth", "analyzers",
      "mime_type", "filename", "duration", "local_orig", "is_orig", "seen_bytes", "total_bytes",
      "missing_bytes", "overflow_bytes", "timedout", "parent_fuid", "md5", "sha1", "sha256",
      "extracted", "extracted_cutoff", "extracted_size"
    ],
    "notice" => [
      "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
      "note", "msg", "sub", "src", "dst", "p", "n", "peer_descr", "actions", "suppress_for",
      "remote_location.country_code", "remote_location.region", "remote_location.city",
      "remote_location.latitude", "remote_location.longitude"
    ]
  }
end

def filter(event)
  log_type = event.get("zeek_log_type")
  field_data = event.get("zeek_field_data")

  return [event] unless log_type && field_data.is_a?(Array)

  field_names = @field_map[log_type]

  # If we have a field map for this log type, map the data
  if field_names && field_names.length == field_data.length
    field_names.each_with_index do |field_name, index|
      # Skip empty fields
      next if field_data[index].nil? || field_data[index] == "-"

      # Create a structured field name (e.g., 'id.orig_h' becomes nested JSON)
      if field_name.include?(".")
        parts = field_name.split(".")
        current = event
        parts[0..-2].each do |part|
          current[part] ||= {}
          current = current[part]
        end
        current[parts[-1]] = field_data[index]
      else
        event.set(field_name, field_data[index])
      end
    end

    # Set some common top-level fields for easy access
    event.set("src_ip", event.get("id.orig_h")) if event.get("id.orig_h")
    event.set("dest_ip", event.get("id.resp_h")) if event.get("id.resp_h")
    event.set("src_port", event.get("id.orig_p")) if event.get("id.orig_p")
    event.set("dest_port", event.get("id.resp_p")) if event.get("id.resp_p")
  else
    event.tag("zeek_field_mismatch")
  end

  [event]
end