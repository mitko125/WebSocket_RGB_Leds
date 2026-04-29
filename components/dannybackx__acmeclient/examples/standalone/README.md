Work in progress :
- sample appears to work
- cleanup due
- integration with acmeclient C++ source due

This is a modified copy of IDF_PATH/examples/protocols/https_server/simple .

The hardcoded certificates were removed, and the function to start a web server
with them was modified to fetch stuff obtained with ACME.

Part of the work in progress is that this is C language based, and we're building
the C language interface for the ACME component together with this example.

Note that we're using the example component to connect to WiFi, but this isn't very
realistic : a real server would need to have a fixed IP address, and this doesn't do that.
