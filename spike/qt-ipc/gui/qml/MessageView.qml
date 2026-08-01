import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// The QML island — the message list and composer. This is the part that would
// be painful in Widgets: variable-height rows, avatar grouping, custom styling.
Rectangle {
    id: root
    color: "#313338"

    property string channel: "general"

    // Consecutive messages from the same author collapse into one block, the
    // way every modern chat client renders them.
    // Called once per channel switch, before the history streams in.
    function beginChannel(name) {
        root.channel = name
        model.clear()
    }

    function appendMessage(author, colour, body, time, mine, seq) {
        var last = model.count > 0 ? model.get(model.count - 1) : null
        var grouped = last !== null && last.author === author && last.kind === "msg"
        model.append({
            kind: "msg", author: author, colour: colour,
            body: body, time: time, mine: mine === true, grouped: grouped,
            seq: seq === undefined ? 0 : seq
        })
        list.positionViewAtEnd()
    }

    ListModel { id: model }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // ---- channel header -------------------------------------------------
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 48
            color: "#313338"

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 16
                anchors.rightMargin: 16
                spacing: 8

                Text {
                    text: "#"
                    color: "#80848e"
                    font.pixelSize: 22
                    font.bold: true
                }
                Text {
                    text: root.channel
                    color: "#f2f3f5"
                    font.pixelSize: 16
                    font.bold: true
                }
                Rectangle { Layout.fillWidth: true; color: "transparent" }
                Text {
                    text: "end-to-end encrypted"
                    color: "#949ba4"
                    font.pixelSize: 11
                }
            }

            Rectangle {
                anchors.bottom: parent.bottom
                width: parent.width
                height: 1
                color: "#26272b"
            }
        }

        // ---- messages -------------------------------------------------------
        ListView {
            id: list
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: model
            spacing: 0
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: ScrollBar {}

            delegate: Loader {
                width: list.width
                sourceComponent: messageRow

                Component {
                    id: messageRow
                    Rectangle {
                        implicitHeight: content.implicitHeight + (grouped ? 4 : 16)
                        color: hover.hovered ? "#2e3035" : "transparent"

                        HoverHandler { id: hover }

                        RowLayout {
                            id: content
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.topMargin: grouped ? 2 : 10
                            anchors.leftMargin: 16
                            anchors.rightMargin: 16
                            spacing: 12

                            // avatar, or blank space when grouped
                            Item {
                                Layout.alignment: Qt.AlignTop
                                implicitWidth: 38
                                implicitHeight: grouped ? 1 : 38

                                Rectangle {
                                    visible: !grouped
                                    width: 38; height: 38
                                    radius: 19
                                    color: colour
                                    Text {
                                        anchors.centerIn: parent
                                        text: author.length > 0 ? author.charAt(0).toUpperCase() : "?"
                                        color: "#ffffff"
                                        font.pixelSize: 16
                                        font.bold: true
                                    }
                                }
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 2

                                RowLayout {
                                    visible: !grouped
                                    spacing: 8
                                    Text {
                                        text: author
                                        color: colour
                                        font.pixelSize: 14
                                        font.bold: true
                                    }
                                    Text {
                                        text: time
                                        color: "#949ba4"
                                        font.pixelSize: 11
                                    }
                                    Text {
                                        visible: hover.hovered
                                        text: "seq " + seq
                                        color: "#6d6f78"
                                        font.pixelSize: 10
                                    }
                                }

                                Text {
                                    Layout.fillWidth: true
                                    text: body
                                    color: "#dbdee1"
                                    font.pixelSize: 14
                                    wrapMode: Text.Wrap
                                    textFormat: Text.PlainText
                                }
                            }
                        }
                    }
                }
            }
        }

        // ---- composer -------------------------------------------------------
        Item {
            Layout.fillWidth: true
            implicitHeight: 68

            Rectangle {
                anchors.fill: parent
                anchors.margins: 16
                anchors.topMargin: 4
                radius: 8
                color: "#383a40"

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 16
                    anchors.rightMargin: 8
                    spacing: 8

                    TextField {
                        id: composer
                        Layout.fillWidth: true
                        placeholderText: "Message #" + root.channel
                        color: "#dbdee1"
                        placeholderTextColor: "#6d6f78"
                        font.pixelSize: 14
                        background: null
                        onAccepted: root.submit()
                    }

                    Button {
                        text: "Send"
                        enabled: composer.text.length > 0
                        onClicked: root.submit()
                    }
                }
            }
        }
    }

    function submit() {
        if (composer.text.length === 0)
            return
        bridge.send(composer.text)
        composer.text = ""
    }
}
