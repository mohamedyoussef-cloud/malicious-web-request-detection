import streamlit as st
from detector import predict_url


st.set_page_config(
    page_title="Malicious Web Request Detection",
    page_icon="🛡️",
    layout="centered"
)


st.title("Malicious Web Request Detection")


url = st.text_input(
    "Enter a URL or web request:",
    placeholder="https://example.com/search?q=test"
)


if st.button("Analyze URL", use_container_width=True):
    if not url.strip():
        st.warning("Please enter a URL first.")
    else:
        try:
            result = predict_url(url)

            label = result.get("label", "Unknown")

            if label == "Safe":
                st.success("Safe Request")
            elif label == "Phishing":
                st.warning("Phishing Request Detected")
            elif label == "Defacement":
                st.error("Defacement Detected")
            else:
                st.error("Malicious Request Detected")

            st.metric("Risk Score", result.get("confidence", 0))

            st.write("### Detection Type")
            st.write(label)

            st.write("### Reasons")
            for reason in result.get("reasons", []):
                st.write(f"- {reason}")

            with st.expander("Technical Features"):
                st.json(result.get("features", {}))

        except Exception as e:
            st.error(f"Error: {e}")


st.divider()
st.caption("Project")
