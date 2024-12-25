package nctu.winlab.bridge;

import org.onlab.packet.MacAddress;
import org.onosproject.net.PortNumber;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

class PortTable {
    private Map<MacAddress, PortNumber> ports = new HashMap<>();

    public PortNumber put(MacAddress mac, PortNumber port) {
        return ports.put(mac, port);
    }

    public Optional<PortNumber> getPort(MacAddress mac) {
        return Optional.ofNullable(ports.get(mac));
    }
}
