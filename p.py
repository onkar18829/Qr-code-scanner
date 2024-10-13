import cv2
from pyzbar.pyzbar import decode
import requests
import base64
import streamlit as st
import numpy as np
from PIL import Image

API_KEY = 'c15a97c6df2f0d2e6e60e805bdbfbe24cf5695fc154046c711994199b36afc4a'

# Function to check the safety of URL using VirusTotal API
def check_safety_with_virustotal(url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": API_KEY
    }
    
    response = requests.post(api_url, headers=headers, data={"url": url})
    if response.status_code == 200:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        report_response = requests.get(report_url, headers=headers)
        if report_response.status_code == 200:
            result = report_response.json()
            score = result['data']['attributes']['last_analysis_stats']
            if score['malicious'] > 0:
                return "Unsafe"
            else:
                return "Safe"
        else:
            st.error(f"Error fetching report: {report_response.status_code}, {report_response.text}")
    else:
        st.error(f"Error submitting URL: {response.status_code}, {response.text}")
    return "Error"

# Function to scan QR code using Pyzbar
def scan_qr_code(image):
    decoded_objects = decode(image)
    if decoded_objects:
        for obj in decoded_objects:
            qr_data = obj.data.decode("utf-8")  # Get QR code data
            safety_status = check_safety_with_virustotal(qr_data)
            return qr_data, safety_status
    return None, None

# Streamlit UI starts here
st.title("QR Code Safety Checker")
st.write("Choose between uploading an image or using your webcam to scan a QR code.")

# Create a menu with two options: Upload QR or Scan with Camera
menu_options = ["Upload QR Code", "Scan with Camera"]
choice = st.selectbox("Choose an option:", menu_options)

# If user chooses to upload a QR code image
if choice == "Upload QR Code":
    uploaded_file = st.file_uploader("Upload a QR Code Image", type=['png', 'jpg', 'jpeg'])
    if uploaded_file is not None:
        # Load the uploaded image using PIL
        image = Image.open(uploaded_file)

        # Convert the image to OpenCV format
        opencv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)

        # Display the uploaded image
        st.image(image, caption="Uploaded QR Code Image", use_column_width=True)

        # Scan QR code
        qr_data, safety_status = scan_qr_code(opencv_image)

        if qr_data:
            st.write(f"**QR Code Data**: {qr_data}")
            st.write(f"**Safety Status**: {safety_status}")
            if safety_status == "Safe":
                st.success("The URL is Safe!")
            else:
                st.error("The URL is Unsafe!")
        else:
            st.warning("No QR code detected in the image. Please upload a valid QR code.")

# If user chooses to scan QR code using the camera
elif choice == "Scan with Camera":
    st.write("The camera will start scanning for QR codes automatically.")
    
    # Initialize webcam feed
    cap = cv2.VideoCapture(0)
    stframe = st.empty()  # To hold the video feed
    
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            st.error("Failed to grab frame from webcam.")
            break
        
        # Convert the frame to RGB (needed for Streamlit to display)
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        
        # Scan QR code from the live frame
        qr_data, safety_status = scan_qr_code(frame)
        
        # Display results on the frame
        if qr_data:
            cv2.putText(frame, f"Status: {safety_status}", (50, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, 
                        (0, 255, 0) if safety_status == "Safe" else (0, 0, 255), 2)
            stframe.image(frame_rgb, channels="RGB")
            st.write(f"**QR Code Data**: {qr_data}")
            st.write(f"**Safety Status**: {safety_status}")
            if safety_status == "Safe":
                st.success("The URL is Safe!")
            else:
                st.error("The URL is Unsafe!")
        else:
            # Continuously display the live frame in the Streamlit app
            stframe.image(frame_rgb, channels="RGB")
    
    # Release the webcam feed when done
    cap.release()
