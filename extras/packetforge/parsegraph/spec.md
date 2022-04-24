#### Packet Forger JSON Specification Rev 0.1

### 0. Change Logs

2021-10, initialized by Zhang, Qi

### 1. Parse Graph

A Parse Graph is a unidirectional graph. It is consist of a set of nodes and edges. A node represent a network protocol header, and an edge represent the linkage of two protocol headers which is adjacent in the packet. An example of a parse graph have 5 nodes and 6 edges.

[![](https://mermaid.ink/img/eyJjb2RlIjoiZ3JhcGggVERcbiAgICBBKChNQUMpKSAtLT4gQigoSVB2NCkpXG4gICAgQSgoTUFDKSkgLS0-IEMoKElQdjYpKVxuICAgIEIgLS0-IEQoKFRDUCkpXG4gICAgQyAtLT4gRCgoVENQKSlcbiAgICBCIC0tPiBFKChVRFApKVxuICAgIEMgLS0-IEUoKFVEUCkpXG4gICAgIiwibWVybWFpZCI6eyJ0aGVtZSI6ImRhcmsifSwidXBkYXRlRWRpdG9yIjpmYWxzZSwiYXV0b1N5bmMiOnRydWUsInVwZGF0ZURpYWdyYW0iOmZhbHNlfQ)](https://mermaid-js.github.io/mermaid-live-editor/edit#eyJjb2RlIjoiZ3JhcGggVERcbiAgICBBKChNQUMpKSAtLT4gQigoSVB2NCkpXG4gICAgQSgoTUFDKSkgLS0-IEMoKElQdjYpKVxuICAgIEIgLS0-IEQoKFRDUCkpXG4gICAgQyAtLT4gRCgoVENQKSlcbiAgICBCIC0tPiBFKChVRFApKVxuICAgIEMgLS0-IEUoKFVEUCkpXG4gICAgIiwibWVybWFpZCI6IntcbiAgXCJ0aGVtZVwiOiBcImRhcmtcIlxufSIsInVwZGF0ZUVkaXRvciI6ZmFsc2UsImF1dG9TeW5jIjp0cnVlLCJ1cGRhdGVEaWFncmFtIjpmYWxzZX0)

A Node or an Edge is described by a json object. There is no json representation for a parse graph, software should load all json objects of nodes and edges then build the parse graph logic in memory.

### 2. Node

A json object of Node will include below properties:

* **type**

  This should always be "node".

* **name**

  This is the name of the protocol.

* **layout**

  This is an array of fields in the protocol header which also imply the bit order. For example, json object of mac header as below:
  ```
  {
      "type" : "node",
      "name" : "mac",
      "layout" : [
          {
              "name" : "src",
              "size" : "48",
              "format" : "mac",
          },
          {
              "name" : "dst",
              "size" : "48",
              "format" : "mac",
          },
          {
              "name" : "ethertype",
              "size" : "16",
          }
      ]
  }
  ```

  For each field, there are properties can be defined:

    * **name**

      The name of the field, typically it should be unique to all fields in the same node, except when it is "reserved".

    * **size**

      Size of the field, note, the unit is "bit" but not "byte".
      Sometime a field's size can be decided by another field's value, for example, a geneve header's "options" field's size is decided by "optlen" field's value, so we have below:

      ```
      "name" : "geneve",
      "layout" : [

          ......

          {
              "name" : "reserved",
              "size" : "8"
          },
          {
              "name" : "options",
              "size" : "optlen<<5"
          }
      ],
      ```
      Since when "optlen" increases 1 which means 4 bytes (32 bits) increase of "options"'s size so the bit value should shift left 5.

    * **format**

      Defined the input string format of the value, all formats are described in the section **Input Format** which also described the default format if it is not explicitly defined.

    * **default**

      Defined the default value of the field when a protocol header instance is created by the node. If not defined, the default value is always 0. The default value can be overwritten when forging a packet with specific value of the field. For example, we defined the default ipv4 address as below:

      ```
      "name" : "ipv4",
      "layout" : [

          ......

          {
              "name" : "src",
              "size" : "32",
              "format" : "ipv4",
              "default" : "1.1.1.1"
          },
          {
              "name" : "dst",
              "size" : "32",
              "format" : "ipv4",
              "default" : "2.2.2.2"
          }
      ]
      ```

    * **readonly**

      Define if a field is read only or not, typically it will be used together with "default". For example, the version of IPv4 header should be 4 and can't be overwritten.

      ```
      "name" : "ipv4",
      "layout" : [
          {
              "name" : "version",
              "size" : "4",
              "default" : "4",
              "readonly" : "true"
          },
          ......
      ],
      ```
      A reserved field implies it is "readonly" and should always be 0.

    * **optional**

      A field could be optional depends on some flag as another field. For example, the GRE header has couple optional fields.

      ```
      "name" : "gre",
      "layout" : [
          {
              "name" : "c",
              "size" : "1",
          },
          {
              "name" : "reserved",
              "size" : "1",
          },
          {
              "name" : "k",
              "size" : "1",
          },
          {
              "name" : "s",
              "size" : "1",
          },

          ......

          {
              "name" : "checksum",
              "size" : "16",
              "optional" : "c=1",
          },
          {
              "name" : "reserved",
              "size" : "16",
              "optional" : "c=1",
          },
          {
              "name" : "key",
              "size" : "32",
              "optional" : "k=1"
          },
          {
              "name" : "sequencenumber",
              "size" : "32",
              "optional" : "s=1"
          }
      ]
      ```

      The expresion of an optional field can use "**&**" or "**|**" combine multiple conditions, for example for gtpu header, we have below optional fields.

      ```
      "name" : "gtpu",
      "layout" : [

          ......

          {
              "name" : "e",
              "size" : "1"
          },
          {
              "name" : "s",
              "size" : "1"
          },
          {
              "name" : "pn",
              "size" : "1"
          },

          ......

          {
              "name" : "teid",
              "size" : "16"
          },
          {
              "name" : "sequencenumber",
              "size" : "16",
              "optional" : "e=1|s=1|pn=1",
          },

          ......
      ]

      ```

    * **autoincrease**

      Some field's value cover the length of the payload or size of an optional field in the same header, so it should be auto increased during packet forging. For example the "totallength" of ipv4 header is a autoincrease feild.

      ```
      "name" : "ipv4",
      "layout" : [

          ......

          {
              "name" : "totallength",
              "size" : "16",
              "default" : "20",
              "autoincrease" : "true",
          },

          ......

      ]
      ```

      A field which is autoincrease also imply its readonly.

    * **increaselength**

      Typically this should only be enabled for an optional field to trigger another field's autoincrease. For example, the gtpc's "messagelength" field cover all the data start from field "teid", so its default size is 4 bytes which cover sequencenumber + 8 reserved bit, and should be increased if "teid" exist or any payload be appended.

      ```
      "name" : "gtpc",
      "layout" : [

          ......

          {
              "name" : "messagelength",
              "size" : "16",
              "default" : "4",
              "autoincrease" : "true",
          },
          {
              "name" : "teid",
              "size" : "32",
              "optional" : "t=1",
              "increaselength" : "true"
          },
          {
              "name" : "sequencenumber",
              "size" : "24",
          },
          {
              "name" : "reserved",
              "size" : "8",
          }
      ]
      ```

* **attributes**

  This defines an array of attributes, the attribute does not define the data belongs to current protocol header, but it impact the behaviour during applying actions of an edge when the protocol header is involved. For example, a geneve node has attribute "udpport" which define the udp tunnel port, so when it is appended after a udp header, the udp header's dst port is expected to be changed to this value.

  ```
  "name" : "geneve",

  "fields" : [

      ......

  ],
  "attributes" : [
      {
          "name" : "udpport",
          "size" : "16",
          "default" : "6081"
      }
  ]
  ```

  An attribute can only have below properties which take same effect when they are in  field.

  * name
  * size  (must be fixed value)
  * default
  * format

### 3. Edge

  A json object of Edge will include below properties:

  * **type**

    This should always be "edge".

  * **start**

    This is the start node of the edge.

  * **end**

    This is the end node of the edge.

  * **actions**

    This is an array of actions the should be applied during packet forging.
    For example, when append a ipv4 headers after a mac header, the "ethertype" field of mac should be set to "0x0800":

    ```
    {
        "type" : "edge",
        "start" : "mac",
        "end" : "ipv4",
        "actions" : [
            {
                "dst" : "start.ethertype",
                "src" : "0x0800"
            }
        ]
    }
    ```
    Each action should have two properties:

    * **dst**

      This describe the target field to set, it is formatted as <node>.<field>
      node must be "start" or "end".

    * **src**

      This describe the value to set, it could be a const value or same format as dst's.
      For example when append a vlan header after mac, we will have below actions:

      ```
      {
          "type" : "edge",
          "start" : "mac",
          "end" : "vlan",
          "actions" : [
              {
                  "dst" : "start.ethertype",
                  "src" : "end.tpid"
              },
              {
                  "dst" : "end.ethertype",
                  "src" : "start.ethertype"
              }
          ]
      }
      ```


  To avoid duplication, multiple edges can be aggregate into the one json object if there actions are same. So, multiple node name can be added to **start** or **end** with seperateor "**,**".

  For example, all ipv6 and ipv6 extention header share the same actions when append a udp header

  ```
  {
      "type" : "edge",
      "start" : "ipv6,ipv6srh,ipv6crh16,ipv6crh32",
      "end" : "udp",
      "actions" : [
          {
              "dst" : "start.nextheader",
              "src" : "17"
          }
      ]
  }
  ```

  Another examples is gre and nvgre share the same actions when be appanded after a ipv4 header:
  ```
  {
      "type" : "edge",
      "start" : "ipv4",
      "end" : "gre,nvgre",
      "actions" : [
          {
              "dst" : "start.protocol",
              "src" : "47"
          }
      ]
  }
  ```

### 4. Path

A path defines a sequence of nodes which is the input parameter for a packet forging, a packet forging should fail if the path can't be recognised as a subgraph of the parser graph.

A json object of a path should include below properties:

* **type**

  This should always be "path".

* **stack**

  This is an array of node configurations which also imply the protocol header sequence of a packet. Below is an example to forge an ipv4 / udp packet with default value.

  ```
  {
      "type" : "path",
      "stack" : [
          {
              "header" : "mac"
          },
          {
              "header" : "ipv4"
          },
          {
              "header" : "udp"
          },
      ]
  }
  ```

  A node configuration can have below properties:

  * **header**

    This is a protocol name (a node name).

  * **fields**

    This is an array of 3 member tuples:

    * **name**

      The name of the field or attribute that belongs to the node, note a readonly field should not be selected.

    * **value**

      The value to set the field or attribute.

    * **mask**

      This is optional, if it is not defined, corresponding bit of the mask should be set to 0, and it should be ignored for an attribute.

* **actions**

  This is optional. When this json file is the input of flow adding commands, it can be used directly as the flow rule's action.

  An example to forge a ipv4 packet with src ip address 192.168.0.1 and dst ip address 192.168.0.2, also take ip address as mask.

  ```
  {
      "type" : "path",
      "stack" : [
          {
              "header" : "mac",
          },
          {
              "header" : "ipv4",
              "fields" : [
                  {
                      "name" : "src",
                      "value" : "192.168.0.1",
                      "mask" : "255.255.255.255"
                  },
                  {
                      "name" : "dst",
                      "value" : "192.168.0.2",
                      "mask" : "255.255.255.255"
                  }
              ]
          }
      ],
      "actions" : "redirect-to-queue 3"
  }
  ```


### 5. Input Format

Every field or attribute is associated with an **Input Format**, so the software can figure out how to parse default value in the node or a config value in the path.

Currently we have 8 predefined format and don't support customised format.

* **u8**

  accept number from 0 to 255 or hex from 0x0 to 0xff.

* **u16**

  accept number from 0 to 65535 or hex from 0x0 to 0xffff.

* **u32**

  accept number from 0 to 4294967295 or hex from 0x0 to 0xffffffff

* **u64**

  accept number from 0 to 2^64 -1 or hex from 0x0 to 0xffffffffffffffff

* **mac**

  accept xx:xx:xx:xx:xx:xx , x in hex from 0 to f

* **ipv4**

  accept n.n.n.n , n from 0 to 255

* **ipv6**

  accept xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx, x in hex from 0 to f

* **bytearray**

  accept u8,u8,u8.....

If format is not defined for a field or attribute, the default format will be selected base on size as below, and the MSB should be ignored by software if the value exceeds the limitation.

| Size          | Default Format |
| ------------- | -------------- |
| 1 - 8         | u8             |
| 9 - 16        | u16            |
| 17 - 32       | u32            |
| 33 - 64       | u64            |
| > 64          | bytearray      |
| variable size | bytearray      |
