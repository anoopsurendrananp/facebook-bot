'use strict';

require('dotenv').config();

// Imports dependencies and set up http server
const
    request = require('request'),
    express = require('express'),
    crypto = require('crypto'),
    bodyParser = require('body-parser'),
    AssistantV1 = require('watson-developer-cloud/assistant/v1'),
    redis = require('redis'),
    https = require('https'),
    app = express().use(bodyParser.json({ verify: verifyRequestSignature })); // creates express http server

let redis_client = redis.createClient(process.env.REDIS_PORT, process.env.REDIS_HOST);

redis_client.on('connect', function () {
    console.log('Redis client connected');
});

redis_client.on('error', function (err) {
    console.log('Something went wrong ' + err);
});

/**
 * Use this to clear Redis content
 */

/*redis_client.flushall((err, response)=>{
    if(err) {
      console.log('Redis Everything cleared err', err)
    } else {
        console.log('Redis Everything cleared', response);
    }
}) */


const APP_SECRET = process.env.MESSENGER_APP_SECRET;

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = process.env.MESSENGER_VALIDATION_TOKEN;

const PAGE_ACCESS_TOKEN = process.env.MESSENGER_PAGE_ACCESS_TOKEN;

let assistant = new AssistantV1({
    username: process.env.WATSON_USERNAME,
    password: process.env.WATSON_PASSWORD,
    version: '2018-02-16'
});

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN)) {
    console.error("Missing messenger credentials");
    process.exit(1);
}

// Accepts GET requests at /webhook endpoint
app.get('/webhook', function (req, res) {
    if (req.query['hub.mode'] === 'subscribe' &&
        req.query['hub.verify_token'] === VALIDATION_TOKEN) {
        console.log("Webhook validation success.", req.query['hub.challenge']);
        res.status(200).send(req.query['hub.challenge']);
    } else {
        console.error("Failed validation. Make sure the validation tokens match.");
        res.sendStatus(403);
    }
});



// Accepts POST requests at /webhook endpoint
app.post('/webhook', function (req, res) {
    console.log('POST request', req.body)
    var data = req.body;

    // Make sure this is a page subscription
    if (data.object == 'page') {
        // Iterate over each entry
        // There may be multiple if batched
        data.entry.forEach(function (pageEntry) {
            var pageID = pageEntry.id;
            var timeOfEvent = pageEntry.time;

            // Iterate over each messaging event
            pageEntry.messaging.forEach(function (messagingEvent) {
                if (messagingEvent.optin) {
                    receivedAuthentication(messagingEvent);
                } else if (messagingEvent.message) {
                    var context = {};
                    var prev_context = {};
                    var legit_query = '';
                    var senderInfo = messagingEvent.sender.id;
                    var user_query = messagingEvent.message.text;
                    redis_client.exists(process.env.MESSENGER_APP_SECRET.concat(senderInfo), function (err, reply) {
                        if (!err) {
                            if (reply === 1) {
                                console.log("Key exists");
                            } else {
                                console.log("Does't exists");
                                redis_client.set(process.env.MESSENGER_APP_SECRET.concat(senderInfo), JSON.stringify({ context, prev_context, legit_query }));
                            } 

                            receivedMessage(user_query, senderInfo, messagingEvent);
                       }
                    }); 
                } else if (messagingEvent.delivery) {
                    receivedDeliveryConfirmation(messagingEvent);
                } else if (messagingEvent.postback) {
                    receivedPostback(messagingEvent);
                } else if (messagingEvent.read) {
                    receivedMessageRead(messagingEvent);
                } else if (messagingEvent.account_linking) {
                    receivedAccountLink(messagingEvent);
                } else {
                    console.log("Webhook received unknown messagingEvent: ", messagingEvent);
                }
            });
        });

        // Assume all went well.
        //
        // You must send back a 200, within 20 seconds, to let us know you've
        // successfully received the callback. Otherwise, the request will time out.
        res.sendStatus(200);
    }
});


app.get('/authorize', function (req, res) {
    var accountLinkingToken = req.query.account_linking_token;
    var redirectURI = req.query.redirect_uri;

    // Authorization Code should be generated per user by the developer. This will
    // be passed to the Account Linking callback.
    var authCode = "1234567890";

    // Redirect users to this URI on successful login
    var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

    res.render('authorize', {
        accountLinkingToken: accountLinkingToken,
        redirectURI: redirectURI,
        redirectURISuccess: redirectURISuccess
    });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
    var signature = req.headers["x-hub-signature"];

    if (!signature) {
        // For testing, let's log an error. In production, you should throw an
        // error.
        console.error("Couldn't validate the signature.");
    } else {
        var elements = signature.split('=');
        var method = elements[0];
        var signatureHash = elements[1];

        var expectedHash = crypto.createHmac('sha1', APP_SECRET)
            .update(buf)
            .digest('hex');

        if (signatureHash != expectedHash) {
            throw new Error("Couldn't validate the request signature.");
        }
    }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfAuth = event.timestamp;

    // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
    // The developer can set this to an arbitrary value to associate the
    // authentication callback with the 'Send to Messenger' click event. This is
    // a way to do account linking when the user clicks the 'Send to Messenger'
    // plugin.
    var passThroughParam = event.optin.ref;

    console.log("Received authentication for user %d and page %d with pass " +
        "through param '%s' at %d", senderID, recipientID, passThroughParam,
        timeOfAuth);

    // When an authentication is received, we'll send a message back to the sender
    // to let them know it was successful.
    sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */

function receivedMessage(user_query, senderInfo, event) {
    var message = event.message;

    // You may get a text or attachment but not both
    var messageText = message.text;
    var messageAttachments = message.attachments;

    if (messageText) {
        callWatson(user_query, senderInfo, null);
    } else if (messageAttachments) {
        sendTextMessage(senderInfo, "Message with attachment received");
    }
}

/*
 * This function interacts with the workspace
 * 
 * The response is converted into facebook-sentable format
*/

function callWatson(user_query, senderInfo, isWelcomeMsg) {

    redis_client.get(process.env.MESSENGER_APP_SECRET.concat(senderInfo), function (err, reply) {
        if (err) {
            console.log(err);
            return;
        }
        let context = {};
        var sender = JSON.parse(reply);

        if (isWelcomeMsg == null) {
            context = sender.context;
        }

        var prev_context = sender.prev_context; 

        assistant.message({
            input: { text: user_query },
            workspace_id: process.env.WATSON_WORKSPACE,
            context: context
        }, function (err, response) {
            if (err) {
                console.error(err);
            } else {

               sender.legit_query = user_query;

                // rewrite/update the context in existing sender object
                sender.prev_context = sender.context;
                sender.context = response.context;

                redis_client.set(process.env.MESSENGER_APP_SECRET.concat(senderInfo), JSON.stringify(sender)); 
                let messageData = {};
                //   console.log(JSON.stringify(response, null, 2));
                console.log(response.output.text[0]);

                // sendReadReceipt(senderInfo);
                // sendTypingOn(senderInfo);

                if (response.output.attachment) {
                    messageData = {
                        recipient: {
                            id: senderInfo
                        },
                        message: {
                            attachment: {
                                type: response.output.attachment.type,
                                payload: {
                                    url: response.output.attachment.url
                                }
                            }
                        }
                    };
                } else if (response.output.button) {
                    messageData = {
                        recipient: {
                            id: senderInfo
                        },
                        message: {
                            attachment: {
                                type: "template",
                                payload: {
                                    template_type: "button",
                                    text: response.output.text[0],
                                    buttons: response.output.button
                                }
                            }
                        }
                    };
                } else {
                    messageData = {
                        recipient: {
                            id: senderInfo
                        },
                        message: {
                            text: response.output.text[0]
                        }
                    };

                    if (response.output.quick_reply) {
                        messageData.message.quick_replies = response.output.quick_reply
                    }
                }
                callSendAPI(messageData);
            }
        });
    });
}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var delivery = event.delivery;
    var messageIDs = delivery.mids;
    var watermark = delivery.watermark;
    var sequenceNumber = delivery.seq;

    if (messageIDs) {
        messageIDs.forEach(function (messageID) {
            console.log("Received delivery confirmation for message ID: %s",
                messageID);
        });
    }

    console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 *
 */
function receivedPostback(event) {
    var senderID = event.sender.id;
    let isWelcomeMsg = {
        context: {}
    };

    callWatson('', senderID, isWelcomeMsg);
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 *
 */
function receivedMessageRead(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;

    // All messages before watermark (a timestamp) or sequence have been seen.
    var watermark = event.read.watermark;
    var sequenceNumber = event.read.seq;

    console.log("Received message read event for watermark %d and sequence " +
        "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 *
 */
function receivedAccountLink(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;

    var status = event.account_linking.status;
    var authCode = event.account_linking.authorization_code;

    console.log("Received account link event with for user %d with status %s " +
        "and auth code %s ", senderID, status, authCode);
}




/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: messageText
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
    console.log('incv')
    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "mark_seen"
    };

    callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {

    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "typing_on"
    };

    callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
    console.log("Turning typing indicator off");

    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "typing_off"
    };

    callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "button",
                    text: "Welcome. Link your account.",
                    buttons: [{
                        type: "account_link",
                        url: SERVER_URL + "/authorize"
                    }]
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
    request({
        uri: 'https://graph.facebook.com/v2.6/me/messages',
        qs: { access_token: PAGE_ACCESS_TOKEN },
        method: 'POST',
        json: messageData

    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            var recipientId = body.recipient_id;
            var messageId = body.message_id;

            if (messageId) {
                console.log("Successfully sent message with id %s to recipient %s",
                    messageId, recipientId);
            } else {
                console.log("Successfully called Send API for recipient %s",
                    recipientId);
            }
        } else {
            console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
        }
    });
}

function addPersistentMenu(){

 request({
    url: 'https://graph.facebook.com/v2.6/me/messenger_profile',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json:{
"persistent_menu":[
    {
      "locale":"default",
      "composer_input_disabled":true,
      "call_to_actions":[
        {
            "title": "Right job",
            "payload": "<DEVELOPER_DEFINED_PAYLOAD>",
            "type": "postback"
        },
        {
            "title": "Questions on application",
            "payload": "<DEVELOPER_DEFINED_PAYLOAD>",
            "type": "postback"
        },
        {
            "title": "Learn about Siemens",
            "payload": "<DEVELOPER_DEFINED_PAYLOAD>",
            "type": "postback"
        }
      ]
    },
    {
      "locale":"zh_CN",
      "composer_input_disabled":false
    }
    ]
    }

}, function(error, response, body) {
    
    if (error) {
        console.log('Error sending messages: ', error)
    } else if (response.body.error) {
        console.log('Error: ', response.body.error)
    } else {
        console.log('Body', body)
    }
})

}

app.listen(process.env.PORT, () => {
    console.log(`webhook is listening at ${process.env.PORT}`);
});

module.exports = app;


