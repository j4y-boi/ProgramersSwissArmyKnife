# Programmer's Swiss Army Knife
# Made by j4y_boi
# https://github.com/j4y-boi

import customtkinter as ctk
from tkinter import filedialog, messagebox
import base64, uuid, hashlib, qrcode
import urllib.parse
from io import BytesIO
from PIL import Image
import sys
import string, random

ctk.set_appearance_mode("system")  # incase someone uses light mode (waht is wrong with u)
ctk.set_default_color_theme("blue")

optionsList = ["Base64 Encode/Decode","Hex Encode/Decode","Binary","UUID","URL Encode/Decode","Hashes","QR Code","Random String Generator"] #guess whos too lazy to edit multiple things (couldnt be me :P)
optionChosen = 0

def b64encode(string: str):
    return base64.b64encode(string.encode("ascii")).decode("ascii")

def b64decode(string: str): #wowoowowowo b64????
    try:
        return base64.b64decode(string.encode("ascii")).decode("ascii")
    except (base64.binascii.Error, UnicodeDecodeError):
        return ""
    
def generateUUID(version):
    version = str(version)
    version = version[-1:]

    if version == "1":
        return uuid.uuid1()
    elif version == "4":
        return uuid.uuid4()
    else:
        return "hm? invalid version..."

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Programmer's Swiss Army Knife")
        self.geometry("800x450")
        self.resizable(False,False)

        try: #finally came around fixing this annoying problem
            exeLocal = sys._MEIPASS #almost forgot this for the exe
            self.wm_iconbitmap(fr"{exeLocal}/logo.ico")
        except:
            print("yeah no, this isn't an exe hmmmm")

        self.grid_columnconfigure(0)
        self.grid_rowconfigure(0, weight=1)

        self.options_frame = ctk.CTkScrollableFrame(self, width=200, height=300)
        self.options_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ns")

        self.widget_frame = ctk.CTkFrame(self, width=525, height=300)
        self.widget_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        self.widget_frame.grid_columnconfigure(0, weight=1)
        self.widget_frame.grid_rowconfigure(0)

        self.widget_frame.grid_propagate(False)

        # wowowoow options
        self.options = optionsList
        for option in self.options:
            button = ctk.CTkButton(self.options_frame, text=option, command=lambda opt=option: self.show_widget(opt))
            button.pack(pady=5, padx=5, fill="x")

        self.input_textbox = None
        self.output_textbox = None
        self.choicebox = None
        self.image = None

    def show_widget(self, option):
        global optionChosen

        # reset the widget before doin anything
        for widget in self.widget_frame.winfo_children():
            widget.destroy()

        if option == optionsList[0]:
            optionChosen = 0

            # just the title lool also cant be bothered with THIS \/ yep im pointing at text
            title_label = ctk.CTkLabel(self.widget_frame, text=optionsList[optionChosen], font=("Arial", 24, "bold"))
            title_label.grid(row=0, column=0, pady=(20, 5))
            #fancy line
            underline_canvas = ctk.CTkCanvas(self.widget_frame, height=2, width=300, bg="white", bd=0, highlightthickness=0)
            underline_canvas.grid(row=1, column=0)

            #start content

            input_label = ctk.CTkLabel(self.widget_frame, text="Input:")
            input_label.grid(row=2, column=0, pady=(20, 5))

            self.input_textbox = ctk.CTkEntry(self.widget_frame, width=250)
            self.input_textbox.grid(row=3, column=0, padx=10, pady=5)
            self.input_textbox.bind("<KeyRelease>", self.update_output)

            output_label = ctk.CTkLabel(self.widget_frame, text="Output (You can can enter b64 here too! :0):")
            output_label.grid(row=4, column=0, pady=5)

            self.output_textbox = ctk.CTkEntry(self.widget_frame, width=250)
            self.output_textbox.grid(row=5, column=0, padx=10, pady=5)
            self.output_textbox.bind("<KeyRelease>", self.update_input)

            upload_button = ctk.CTkButton(self.widget_frame, text="Convert File to b64", command=self.upload_file)
            upload_button.grid(row=6, column=0, pady=(10, 20))
    
        if option == optionsList[1]:
            optionChosen = 1

            title_label = ctk.CTkLabel(self.widget_frame, text=optionsList[optionChosen], font=("Arial", 24, "bold"))
            title_label.grid(row=0, column=0, pady=(20, 5))
            underline_canvas = ctk.CTkCanvas(self.widget_frame, height=2, width=300, bg="white", bd=0, highlightthickness=0)
            underline_canvas.grid(row=1, column=0)

            #start content

            input_label = ctk.CTkLabel(self.widget_frame, text="Input:")
            input_label.grid(row=2, column=0, pady=(20, 5))

            self.input_textbox = ctk.CTkEntry(self.widget_frame, width=250)
            self.input_textbox.grid(row=3, column=0, padx=10, pady=5)
            self.input_textbox.bind("<KeyRelease>", self.update_output)

            output_label = ctk.CTkLabel(self.widget_frame, text="Output (You can enter Hex here):")
            output_label.grid(row=4, column=0, pady=5)

            self.output_textbox = ctk.CTkEntry(self.widget_frame, width=250)
            self.output_textbox.grid(row=5, column=0, padx=10, pady=5)
            self.output_textbox.bind("<KeyRelease>", self.update_input)

        if option == optionsList[2]:
            optionChosen = 2

            title_label = ctk.CTkLabel(self.widget_frame, text=optionsList[optionChosen], font=("Arial", 24, "bold"))
            title_label.grid(row=0, column=0, pady=(20, 5))
            underline_canvas = ctk.CTkCanvas(self.widget_frame, height=2, width=300, bg="white", bd=0, highlightthickness=0)
            underline_canvas.grid(row=1, column=0)

            #start content

            input_label = ctk.CTkLabel(self.widget_frame, text="Input:")
            input_label.grid(row=2, column=0, pady=(20, 5))

            self.input_textbox = ctk.CTkEntry(self.widget_frame, width=250)
            self.input_textbox.grid(row=3, column=0, padx=10, pady=5)
            self.input_textbox.bind("<KeyRelease>", self.update_output)

            output_label = ctk.CTkLabel(self.widget_frame, text="Output (You can enter Binary here):")
            output_label.grid(row=4, column=0, pady=5)

            self.output_textbox = ctk.CTkEntry(self.widget_frame, width=250)
            self.output_textbox.grid(row=5, column=0, padx=10, pady=5)
            self.output_textbox.bind("<KeyRelease>", self.update_input)

        if option == optionsList[3]:
            optionChosen = 3

            title_label = ctk.CTkLabel(self.widget_frame, text=optionsList[optionChosen], font=("Arial", 24, "bold"))
            title_label.grid(row=0, column=0, pady=(20, 5))
            another_label = ctk.CTkLabel(self.widget_frame, text="dunno why you'd want to use it but sure", font=("Arial", 14))
            another_label.grid(row=2, column=0)
            underline_canvas = ctk.CTkCanvas(self.widget_frame, height=2, bg="white", bd=0, highlightthickness=0)
            underline_canvas.grid(row=3, column=0)
            
            # content starts (lets switch it up a bit)

            self.output_textbox = ctk.CTkEntry(self.widget_frame, width=250,state="readonly")
            self.output_textbox.grid(row=4, column=0, padx=10, pady=(20, 5))

            UUIDver = ctk.StringVar(value="Version 1")

            self.choicebox = ctk.CTkComboBox(self.widget_frame,
                                                values=["Version 1", "Version 4"],
                                                variable=UUIDver,
                                                state="readonly")
            self.choicebox.grid(row=5, column=0, padx=20, pady=10)
            self.choicebox.set("Version 1")  # set initial value

            generate_button = ctk.CTkButton(self.widget_frame, text="Generate", command=self.UUID_update)
            generate_button.grid(row=6, column=0, pady=(10, 20))

        if option == optionsList[4]:
            optionChosen = 4

            title_label = ctk.CTkLabel(self.widget_frame, text=optionsList[optionChosen], font=("Arial", 24, "bold"))
            title_label.grid(row=0, column=0, pady=(20, 5))
            underline_canvas = ctk.CTkCanvas(self.widget_frame, height=2, width=300, bg="white", bd=0, highlightthickness=0)
            underline_canvas.grid(row=1, column=0)

            #start content (nah nvm)

            input_label = ctk.CTkLabel(self.widget_frame, text="Input:")
            input_label.grid(row=2, column=0, pady=(20, 5))

            self.input_textbox = ctk.CTkEntry(self.widget_frame, width=250)
            self.input_textbox.grid(row=3, column=0, padx=10, pady=5)
            self.input_textbox.bind("<KeyRelease>", self.update_output)

            output_label = ctk.CTkLabel(self.widget_frame, text="Output (You can paste an encode URL here):")
            output_label.grid(row=4, column=0, pady=5)

            self.output_textbox = ctk.CTkEntry(self.widget_frame, width=250)
            self.output_textbox.grid(row=5, column=0, padx=10, pady=5)
            self.output_textbox.bind("<KeyRelease>", self.update_input)

        if option == optionsList[5]:
            optionChosen = 5

            title_label = ctk.CTkLabel(self.widget_frame, text=optionsList[optionChosen], font=("Arial", 24, "bold"))
            title_label.grid(row=0, column=0, pady=(20, 5))
            another_label = ctk.CTkLabel(self.widget_frame, text="MD5, SHA-256, those things", font=("Arial", 14))
            another_label.grid(row=1, column=0)
            underline_canvas = ctk.CTkCanvas(self.widget_frame, height=2, width=300, bg="white", bd=0, highlightthickness=0)
            underline_canvas.grid(row=2, column=0)

            input_label = ctk.CTkLabel(self.widget_frame, text="Input:")
            input_label.grid(row=3, column=0, pady=(20, 5))
            self.input_textbox = ctk.CTkEntry(self.widget_frame, width=250)
            self.input_textbox.grid(row=4, column=0, padx=10,)

            output_label = ctk.CTkLabel(self.widget_frame, text="Output:")
            output_label.grid(row=6, column=0)

            #yeah i copy pasted this from the uuid generation, did i regret it? no.
            self.output_textbox = ctk.CTkEntry(self.widget_frame, width=250,state="readonly")
            self.output_textbox.grid(row=7, column=0, padx=10)

            hashType = ctk.StringVar(value="MD5")

            self.choicebox = ctk.CTkComboBox(self.widget_frame,
                                                values=["MD5", "SHA-256"],
                                                variable=hashType,
                                                state="readonly")
            self.choicebox.grid(row=8, column=0, padx=20, pady=10)
            self.choicebox.set("MD5")  # set initial value

            generate_button = ctk.CTkButton(self.widget_frame, text="Generate", command=self.Hash_generate)
            generate_button.grid(row=9, column=0, pady=(10, 20))

            generate_button2 = ctk.CTkButton(self.widget_frame, text="Hash File", command=self.upload_file)
            generate_button2.grid(row=10, column=0)

        if option == optionsList[6]:
            optionChosen = 6

            title_label = ctk.CTkLabel(self.widget_frame, text=optionsList[optionChosen], font=("Arial", 24, "bold"))
            title_label.grid(row=0, column=0, pady=(20, 5))
            underline_canvas = ctk.CTkCanvas(self.widget_frame, height=2, width=300, bg="white", bd=0, highlightthickness=0)
            underline_canvas.grid(row=2, column=0)

            input_label = ctk.CTkLabel(self.widget_frame, text="Input:")
            input_label.grid(row=3, column=0, pady=5)
            self.input_textbox = ctk.CTkEntry(self.widget_frame, width=250)
            self.input_textbox.grid(row=4, column=0, padx=10,)
            self.input_textbox.bind("<KeyRelease>", self.update_output)

            self.image = ctk.CTkLabel(self.widget_frame, text="Your QR Code will come here!")
            self.image.grid(row=5,column=0, pady=20)
        
        if option == optionsList[7]:
            optionChosen = 7

            title_label = ctk.CTkLabel(self.widget_frame, text=optionsList[optionChosen], font=("Arial", 24, "bold"))
            title_label.grid(row=0, column=0, pady=(20, 5))
            another_label = ctk.CTkLabel(self.widget_frame, text="20 characters of randomness", font=("Arial", 14))
            another_label.grid(row=2, column=0)
            underline_canvas = ctk.CTkCanvas(self.widget_frame, height=2, bg="white", bd=0, highlightthickness=0)
            underline_canvas.grid(row=3, column=0)
            
            # content starts (lets switch it up a bit)

            self.output_textbox = ctk.CTkEntry(self.widget_frame, width=250,state="readonly")
            self.output_textbox.grid(row=4, column=0, padx=10, pady=(20, 5))

            generate_button = ctk.CTkButton(self.widget_frame, text="Generate", command=self.generateRandom)
            generate_button.grid(row=6, column=0, pady=(10, 20))


    def generateRandom(self):
        res = ''.join(random.choices(string.ascii_uppercase +string.ascii_lowercase +string.digits,k=20))
        
        self.output_textbox.configure(state="normal")
        self.output_textbox.delete(0, ctk.END) 
        self.output_textbox.insert(0, res)
        self.output_textbox.configure(state="readonly")

    def save_QR(self):
        file_path = filedialog.asksaveasfilename(
            initialfile='qr_code.png',
            defaultextension=".png",
            filetypes=[("PNG Images", "*.png"), ("All Files", "*.*")]
        )

        if file_path:  # Check if the user selected a file
            try:
                qr_gen.save(file_path, format="PNG")
                messagebox.showinfo("Success", f"Successfully saved your QR code!")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while trying to save your QR Code! {e}")


    def UUID_update(self):
       uuidgen = generateUUID(self.choicebox.get())
       self.output_textbox.configure(state="normal")
       self.output_textbox.delete(0, ctk.END) 
       self.output_textbox.insert(0, uuidgen)
       self.output_textbox.configure(state="readonly")

    def Hash_generate(self):
        if self.choicebox.get() == "SHA-256":
            sha256_hash = hashlib.sha256()
            sha256_hash.update(self.input_textbox.get().encode('utf-8'))
            hash_hex = sha256_hash.hexdigest()
        elif self.choicebox.get() == "MD5":
            md5_hash = hashlib.md5()
            md5_hash.update(self.input_textbox.get().encode('utf-8'))
            hash_hex = md5_hash.hexdigest()
        else:
            hash_hex = "[Invalid Hash Algorithm]"

        self.output_textbox.configure(state="normal")
        self.output_textbox.delete(0, ctk.END) 
        self.output_textbox.insert(0, hash_hex)
        self.output_textbox.configure(state="readonly")

    def update_output(self, event=None): #this is really inefficient TODO: fix pls :( 
        if self.input_textbox:
            input_text = self.input_textbox.get()
            if input_text.strip():
                    if optionChosen == 0:
                        self.output_textbox.delete(0, ctk.END)
                        self.output_textbox.insert(0, b64encode(input_text))
                    if optionChosen == 1:
                        self.output_textbox.delete(0, ctk.END)
                        self.output_textbox.insert(0, input_text.encode('utf-8').hex())
                    if optionChosen == 2:
                        self.output_textbox.delete(0, ctk.END)
                        self.output_textbox.insert(0, ' '.join(format(ord(char), '08b') for char in input_text))
                    if optionChosen == 4:
                        self.output_textbox.delete(0, ctk.END)
                        self.output_textbox.insert(0,urllib.parse.quote(input_text))
                    if optionChosen == 6:
                        if not input_text:
                            return  # pls type something
                    
                        if len(input_text) >= 7000:
                            self.image.configure(text="Too long!", image="")
                            return
                        
                        # make qr code
                        qr = qrcode.QRCode(box_size=10, border=2)
                        qr.add_data(input_text)
                        qr.make(fit=True)

                        # make image
                        img = qr.make_image(fill="black", back_color="white")
                        bio = BytesIO()
                        img.save(bio, format="PNG")
                        bio.seek(0)
                        qr_img = Image.open(bio)
                        global qr_gen 
                        qr_gen = qr_img
                        qr_tk = ctk.CTkImage(qr_img, size=[200,200])

                        self.image.configure(image=qr_tk, text="")
                      
                        self.generate_button = ctk.CTkButton(self.widget_frame, text="Save QR Code", command=self.save_QR)
                        self.generate_button.grid(row=6, column=0, pady=(10, 20))

    def update_input(self, event=None):
        if self.output_textbox:
            output_text = self.output_textbox.get()
            self.input_textbox.delete(0, ctk.END)
            if optionChosen == 0:
                decoded_text = b64decode(output_text)
                if decoded_text:
                    self.input_textbox.insert(0, decoded_text)
            if optionChosen == 1:
                try:
                    decoded_text = bytes.fromhex(output_text).decode('utf-8')
                    if decoded_text:
                        self.input_textbox.insert(0, decoded_text)
                except:
                    self.input_textbox.insert(0, "[Not valid Hex]")
            if optionChosen == 2:
                # look at this function isnt it beautiful 
                UNICODE_MAX = 0x10FFFF

                try:
                    decoded_text = ''.join(
                        chr(int(b, 2)) if len(b) == 8 and int(b, 2) <= UNICODE_MAX else f"[Not valid Binary]"
                        for b in output_text.split()  # split when space
                    )
                    self.input_textbox.insert(0, decoded_text)
                except ValueError:
                    self.input_textbox.insert(0, "[Not valid Binary]")
            if optionChosen == 4:
                try:
                    self.input_textbox.insert(0, urllib.parse.unquote(output_text))
                except ValueError:
                    self.input_textbox.insert(0, "[Not valid URL]")



    def upload_file(self):
        if optionChosen == 0:
            file_path = filedialog.askopenfilename()
            if file_path:
                try:
                    with open(file_path, "rb") as file:
                        content = file.read()
                        encoded_content = base64.b64encode(content).decode("ascii")
                        self.input_textbox.delete(0, ctk.END)
                        self.input_textbox.insert(0, "[Encoded your file :o (Check below)]")
                        self.output_textbox.delete(0, ctk.END)
                        self.output_textbox.insert(0, encoded_content)
                except Exception as e:
                    print(f"Error reading file: {e}")
        if optionChosen == 5:
            file_path = filedialog.askopenfilename()
            if file_path:
                try:
                    with open(file_path, "rb") as file:
                        content = file.read()
                        self.input_textbox.delete(0, ctk.END)
                        self.input_textbox.insert(0, "[hashed your file :o (Check below)]")


                        if self.choicebox.get() == "SHA-256":
                            digest = hashlib.file_digest(file, "sha256")
                            hash_hex = digest.hexdigest()  
                        elif self.choicebox.get() == "MD5":
                            digest = hashlib.file_digest(file, "md5")
                            hash_hex = digest.hexdigest()  
                        else:
                            hash_hex = "[Invalid Hash Algorithm]"

                        self.output_textbox.configure(state="normal")
                        self.output_textbox.delete(0, ctk.END) 
                        self.output_textbox.insert(0, hash_hex)
                        self.output_textbox.configure(state="readonly")
                except Exception as e:
                    print(f"Error reading file: {e}")

if __name__ == "__main__":
    app = App()
    app.mainloop()
