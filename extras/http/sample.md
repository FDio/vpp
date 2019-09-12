---
title: Home
---

# VPP Status

### Here's the version...

VPP version: <div id="VPPversion"></div>

build date: <div id="VPPbuilddate"></div>

<div id="like_button_container"></div>


{{< rawhtml >}}
 <!-- Note: when deploying, replace "development.js" with "production.min.js". -->
  <script src="https://unpkg.com/react@16/umd/react.development.js" crossorigin></script>
  <script src="https://unpkg.com/react-dom@16/umd/react-dom.development.js" crossorigin></script>

<script>
'use strict';

const e = React.createElement;

class LikeButton extends React.Component {
  constructor(props) {
    super(props);
    this.state = { liked: false };
  }

  render() {
    if (this.state.liked) {
      return 'You liked this.';
    }

    return e(
      'button',
      { onClick: () => this.setState({ liked: true }) },
      'Like'
    );
  }
}

const domContainer = document.querySelector('#like_button_container');
ReactDOM.render(e(LikeButton), domContainer);
</script>

<script>
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
      console.log (obj);
      document.getElementById("VPPbuilddate").innerHTML=obj.vpp_details.build_date;
      console.log ("back from setting build date");
      console.log (obj.vpp_details.build_date);
      document.getElementById("VPPversion").innerHTML=obj.vpp_details.version;
      console.log ("back from setting version");
      console.log (obj.vpp_details.version);
})
.catch(function(error) {
      console.log(error);
});
</script>
{{< /rawhtml >}}
