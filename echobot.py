from line import LineClient, LineGroup, LineContact

try:
    client = LineClient()
    #client = LineClient(authToken="")
except Exception as error:
    print(error)

while True:
    op_list = []

    for op in client.longPoll():
        op_list.append(op)

    for op in op_list:
        sender      = op[0]
        receiver    = op[1]
        message     = op[2]
        msg         = message
        text        = msg.text
        to          = msg.to
        dari        = msg._from

        if msg.toType == 0 or msg.toType == 1 or msg.toType == 2:
            if msg.toType == 0:
                if dari != client.getProfile().id:
                    to = dari
                else:
                    to = to
            elif msg.toType == 1:
                to = to
            elif msg.toType == 2:
                to = to
            if text is not None:
                print("[ %s ] %s : \'%s\'" % (receiver, sender.name, msg))
                if text.lower() == "hi":
                    client.sendText(to, "Hi too")
