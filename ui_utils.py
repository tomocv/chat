import tkinter as tk


def create_ui(title, send):
    window = tk.Tk()
    window.title(title)

    messages_frame = tk.Frame(window)
    # Variable for messages to be sent
    msg = tk.StringVar()
    msg.set('')
    # Scrollbar to navigate through past messages
    scrollbar = tk.Scrollbar(messages_frame)
    # List that will contain the messages
    msg_list = tk.Listbox(messages_frame, height=20, width=60, yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    msg_list.pack(side=tk.LEFT, fill=tk.BOTH)
    msg_list.pack()
    messages_frame.pack()

    pane = tk.Frame(window)
    pane.pack(fill=tk.BOTH, expand=True)

    label_text = tk.StringVar()
    label_text.set('Message:')
    msg_label = tk.Label(window, textvariable=label_text).pack(side=tk.LEFT)

    entry_field = tk.Entry(window, textvariable=msg)
    entry_field.bind('<Return>', send)
    entry_field.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    send_button = tk.Button(window, text='Send', command=send).pack(side=tk.LEFT)

    window.protocol('WM_DELETE_WINDOW')

    return window, msg, msg_list
