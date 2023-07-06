# Quiz

The Quiz is a simple application that allows users to participate in a quiz consisting of 20 questions. Some questions require a user to provide a written answer, while others require selecting one correct option out of four choices. When participating in the quiz, users are presented with a random selection of 5 questions.

## Project Motivation

The goal of this project is to create an interactive quiz application that challenges users with a variety of questions. The application aims to provide an enjoyable and engaging experience for quiz participants, while also incorporating security measures to protect the integrity of the quiz.

## Getting started

### Key Dependencies & Platforms

- [Java 11](https://www.oracle.com/java/technologies/javase/jdk11-archive-downloads.html): Make sure you have Java 11 installed on your machine. You can download and install it from the official Oracle website or use a Java Development Kit (JDK) distribution suitable for your operating system.

- [Eclipse IDE](https://www.eclipse.org/ide/): I recommend using Eclipse IDE for Java development. Make sure you have Eclipse IDE installed on your machine. You can download it from the Eclipse website and follow the installation instructions.

## Key Features

- `Secure User Registration`: Implement a secure user registration process that generates digital certificates for each user. This ensures the confidentiality and integrity of user information.

- `Protected Quiz Questions`: Apply steganography techniques to securely hide quiz questions within separate images. By using this approach, we prevent unauthorized access to the quiz questions outside of the application.

- `Secure User Authentication`: Enable users to authenticate themselves using their generated digital certificates. This ensures that only authorized users can access the quiz and protects against unauthorized access.

- `Confidentiality and Integrity of Quiz Results`: Implement mechanisms to ensure the confidentiality and integrity of quiz results. User results are stored in a secure manner, allowing only authenticated users to view their own results.

- `Certificate Authority Infrastructure`: Establish a Certificate Authority infrastructure using tools like OpenSSL. This infrastructure enables the issuance and management of digital certificates, ensuring their validity and authenticity.

- `Optimized Cryptographic Algorithms`: Utilize appropriate cryptographic algorithms to ensure the security and efficiency of various operations within the application. Careful consideration is given to the selection and implementation of symmetric and asymmetric algorithms to strike the right balance between performance and security.

## Setup

Before starting the Quiz App, please follow the steps below to set up the necessary libraries and generate the required certificates:

### Add Libraries to Classpath

The Quiz App requires two libraries from the lib folder to be added to the classpath of your project. These libraries provide essential functionality for certificate generation and management. To add the libraries to your classpath, follow these steps:

- Locate the `lib` folder in the project directory.
- Open your project in Eclipse IDE.
- Right-click on your project in the Package Explorer and select `Properties`.
- In the project properties window, select `Java Build Path`.
- Navigate to the `Libraries` tab.
- Click on the `Add JARs`... or `Add External JARs`... button.
- Browse to the lib folder and select the two libraries: `<library1>.jar` and `<library2>.jar`.
- Click `OK` to add the libraries to your project's classpath.

### Generate Certificates

To establish the required Certificate Authority (CA) infrastructure, you need to generate three certificates: one root CA certificate and two subordinate CA certificates. The root CA certificate is a self-signed certificate, while the subordinate CA certificates are signed by the root CA. Follow these steps to generate the certificates:

- Open a `command prompt` or `terminal window`.

- Navigate to the directory where you have OpenSSL installed.

- Generate the root CA certificate:
    ```bash
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -out root-ca.crt -keyout root-ca.key
    ```

- Generate the subordinate CA certificates:
    ```bash
    openssl req -newkey rsa:2048 -sha256 -nodes -out ca1.csr -keyout ca1.key
    openssl x509 -req -in ca1.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out ca1.crt -days 365

    openssl req -newkey rsa:2048 -sha256 -nodes -out ca2.csr -keyout ca2.key
    openssl x509 -req -in ca2.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out ca2.crt -days 365
    ```

- Move the generated certificates (root-ca.crt, root-ca.key, ca1.crt, ca1.key, ca2.crt, ca2.key) to a secure location within your project directory (in this situation root-ca.crt, ca1.crt, ca2.crt should be moved to
certificates folder, while root-ca.key, ca1.key, ca2.key should be moved to keys folder inside certificates
folder).

If someone needs to extract public keys from private keys, they can use OpenSSL or other cryptographic tools to perform the extraction. Here's an example of how to extract the public key from a private key using OpenSSL:

- Open a `command prompt` or `terminal window`.

- Navigate to the directory where you have OpenSSL installed.

- Extract the `public key` from the `private key` file:
    ```bash
    openssl rsa -in private.key -pubout -out public.key
    ```

Replace `private.key` with the path to your private key file, and `public.key` with the desired path for the extracted public key file.

The command will generate a new file (`public.key`) containing the extracted public key.

## Image Steganography

The Quiz App utilizes steganography techniques to hide quiz questions within images. You have to use your own images for the quiz questions, follow the steps below:

- Modify the Source Code: Open the Game.java file located in the src/game directory. Uncomment the doSteganography method by removing the comment markers (//) at the beginning and end of the method.

- Replace the Image Files: Prepare your own set of 20 images that will be used to hide the quiz questions. Make sure the images are in a compatible format (e.g., JPEG, PNG) and have different names.

- Update the File Paths: In the doSteganography method, update the file paths and names to match your own images. Modify the imagePath variable to point to the folder where your new images are located.

- Build and Run the Application: After making the necessary changes, rebuild and run the Quiz App to generate the new steganography images with your own quiz questions embedded.

- Comment the doSteganography Method: Once the new images are generated, comment out the doSteganography method again by adding the comment markers (//) at the beginning and end of the method.

It's important to note that if you choose to delete the existing images, ensure that they are not necessary for other parts of the application. Additionally, make sure to keep a backup of the original images in case you want to revert back to the default setup.

By following these steps, you can use your own images for steganography in the `Quiz` and customize the quiz questions accordingly.