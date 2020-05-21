---
title: Home
---

# VPP Status

### Here's the version...

VPP version: <div id="VPPversion"></div>

build date: <div id="VPPbuilddate"></div>

<div id="like_button_container"></div>

### Show Interface

<p>Enter the interface name, then click "Submit" to display interface stats:</p>

<input id="ifacename" type="text"></input>
<button onclick="getStats()">Get Stats</button>

<div id="ifacestats"></div>

{{< rawhtml >}}

<script>
function getStats() {
    var url="http://192.168.10.1:1234/interface_stats.json?";
    var iface=document.getElementById("ifacename").value;
    url=url.concat(iface);
    fetch(url, {
        method: 'POST',
        mode: 'no-cors',
        cache: 'no-cache',
        headers: {
                 'Content-Type': 'application/json',
        },
})
.then((response) => response.json())
.then(function(obj) {
      console.log(obj)
      var result=obj.interface_stats.name;
      result = result.concat(": rx-pkts: ");
      result = result.concat(obj.interface_stats.rx_packets);
      result = result.concat(" rx-bytes: ");
      result = result.concat(obj.interface_stats.rx_bytes);
      result = result.concat(": tx-pkts: ");
      result = result.concat(obj.interface_stats.tx_packets);
      result = result.concat(" tx-bytes: ");
      result = result.concat(obj.interface_stats.tx_bytes);
      result = result.concat(" drops: ");
      result = result.concat(obj.interface_stats.drops);
      result = result.concat(" ip4: ");
      result = result.concat(obj.interface_stats.ip4);
      result = result.concat(" ip6: ");
      result = result.concat(obj.interface_stats.ip6);

      document.getElementById("ifacestats").innerHTML=result;
})
.catch(function(error) {
      console.log(error);
})}
// unconditionally populate vpp version info ->
fetch('http://192.168.10.1:1234/version.json', {
    method: 'GET',
    mode: 'no-cors',
    cache: 'no-cache',
    headers: {
         'Content-Type': 'application/json',
    },
})
.then((response) => response.json())
.then(function(obj) {
      document.getElementById("VPPbuilddate").innerHTML=obj.vpp_details.build_date;
      document.getElementById("VPPversion").innerHTML=obj.vpp_details.version;
})
.catch(function(error) {
      console.log(error);
});
</script>

{{< /rawhtml >}}
