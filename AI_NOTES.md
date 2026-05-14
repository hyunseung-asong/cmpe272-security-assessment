# AI Notes

I used Codex as the AI assistant for this assessment. It helped me break down the assignment, choose two different designs, write the first version of the code, revise further improvements, and draft the README and design notes.

The two designs were:

- **Approach A:** use mutual TLS, which is like HTTPS where both sides prove who they are.
- **Approach B:** build protection into the file transfer itself by signing the setup messages and encrypting each chunk of the file.

Codex wrote a lot of the starting code, including the sender and receiver scripts, the helper code for reading files in chunks, the key-generation script, and the documentation. I still checked the security-related parts carefully because small mistakes in crypto code can break the whole design. The main things I checked were that certificate checking was actually turned on, public keys were pinned correctly, file chunks used authenticated encryption, and the receiver did not save a partial file as if it were complete.

One issue came up during testing. The first certificates that were generated were missing some certificate metadata that Python/OpenSSL expects. Because of that, the TLS connection failed. Codex helped identify the problem from the error message and update the key-generation script so the certificates worked correctly.

Another thing I made sure not to do was disable certificate verification just to make the TLS error go away. That would have made the demo easier, but it would also defeat the point of mutual authentication. The final code keeps certificate and hostname verification enabled.

Codex did better than expected at quickly turning the assignment requirements into a working project with two separate approaches. It did worse at predicting one Windows-specific TLS shutdown behavior: at first, the sender treated a normal receiver close as an error even after the file had already transferred. The smoke test caught that, and the sender was updated so a successful transfer exits cleanly.

No other AI tools were used in this implementation session.
