// Spike for DESIGN.md §17: the C++/Qt frontend talking to the Rust daemon over
// a unix socket. No FFI, no shared headers, no linked Rust — the only contract
// is newline-delimited JSON on a socket.
//
// Widgets carries the dockable shell (channels, members, log); QML carries the
// message list and composer, which is where Widgets would fight us.

#include <QApplication>
#include <QCloseEvent>
#include <QDockWidget>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QListWidget>
#include <QLocalSocket>
#include <QMainWindow>
#include <QQmlContext>
#include <QQuickItem>
#include <QQuickWidget>
#include <QSettings>
#include <QStatusBar>
#include <QTextBrowser>
#include <QTimer>

static QString socketPath() {
	const QByteArray env = qgetenv("VEIL_SPIKE_SOCKET");
	return env.isEmpty() ? QStringLiteral("/tmp/veil-spike/veil.sock")
	                     : QString::fromLocal8Bit(env);
}

class Window : public QMainWindow {
public:
	Window() {
		setWindowTitle("veil — Qt frontend · Rust daemon · no FFI");
		resize(1180, 760);

		quick_ = new QQuickWidget(this);
		quick_->setResizeMode(QQuickWidget::SizeRootObjectToView);
		quick_->rootContext()->setContextProperty("bridge", this);
		quick_->setSource(QUrl::fromLocalFile(QML_PATH));
		setCentralWidget(quick_);

		channels_ = new QListWidget;
		connect(channels_, &QListWidget::currentTextChanged, this,
		        [this](const QString &name) {
			        if (name.isEmpty())
				        return;
			        channel_ = QString(name).remove(0, 2); // strip "# "
			        request({{"cmd", "select_channel"}, {"channel", channel_}});
		        });
		addDock("Channels", channels_, Qt::LeftDockWidgetArea);

		members_ = new QListWidget;
		addDock("Members", members_, Qt::RightDockWidgetArea);

		log_ = new QTextBrowser;
		auto *logDock = addDock("Daemon log", log_, Qt::BottomDockWidgetArea);
		logDock->hide(); // available from the View menu, out of the way by default

		connect(&sock_, &QLocalSocket::connected, this, [this] {
			log("connected to daemon");
			request({{"cmd", "hello"}});
		});
		connect(&sock_, &QLocalSocket::readyRead, this, &Window::onReadable);
		connect(&sock_, &QLocalSocket::errorOccurred, this, [this] {
			log("socket error: " + sock_.errorString());
			statusBar()->showMessage("daemon unreachable — is it running?");
		});

		sock_.connectToServer(socketPath());
		restoreLayout();
	}

	void selectChannelForDemo(const QString &name) {
		for (int i = 0; i < channels_->count(); ++i)
			if (channels_->item(i)->text().mid(2).startsWith(name))
				channels_->setCurrentRow(i);
	}

	Q_INVOKABLE void send(const QString &text) {
		if (text.isEmpty() || channel_.isEmpty())
			return;
		request({{"cmd", "send"}, {"channel", channel_}, {"text", text}});
	}

protected:
	void closeEvent(QCloseEvent *e) override {
		QSettings s("veil", "gui-spike");
		s.setValue("geometry", saveGeometry());
		s.setValue("state", saveState());
		QMainWindow::closeEvent(e);
	}

private:
	QDockWidget *addDock(const QString &title, QWidget *w, Qt::DockWidgetArea area) {
		auto *d = new QDockWidget(title, this);
		d->setObjectName(title);
		d->setWidget(w);
		addDockWidget(area, d);
		return d;
	}

	void restoreLayout() {
		QSettings s("veil", "gui-spike");
		restoreGeometry(s.value("geometry").toByteArray());
		restoreState(s.value("state").toByteArray());
	}

	void request(const QJsonObject &obj) {
		sock_.write(QJsonDocument(obj).toJson(QJsonDocument::Compact) + "\n");
		sock_.flush();
	}

	void onReadable() {
		buffer_ += sock_.readAll();
		for (;;) {
			const int nl = buffer_.indexOf('\n');
			if (nl < 0)
				return;
			const QByteArray line = buffer_.left(nl);
			buffer_.remove(0, nl + 1);
			if (!line.trimmed().isEmpty())
				onEvent(QJsonDocument::fromJson(line).object());
		}
	}

	void onEvent(const QJsonObject &e) {
		const QString kind = e["event"].toString();

		if (kind == "ready") {
			const QString identity = e["identity"].toString();
			statusBar()->showMessage(
			    "identity " + identity.left(24) + "…   " +
			    QString::number(e["otk_count"].toInt()) + " one-time keys   ·   sealed");
			log("ready — identity " + identity + ", otks " +
			    QString::number(e["otk_count"].toInt()));

			channels_->clear();
			for (const auto c : e["channels"].toArray())
				channels_->addItem("# " + c.toString());
			channels_->setCurrentRow(0); // triggers select_channel

			members_->clear();
			for (const auto m : e["members"].toArray()) {
				const auto o = m.toObject();
				auto *item = new QListWidgetItem(
				    (o["online"].toBool() ? "● " : "○ ") + o["name"].toString());
				item->setForeground(QColor(o["colour"].toString()));
				members_->addItem(item);
			}
			return;
		}

		if (kind == "history") {
			const QString channel = e["channel"].toString();
			auto *root = quick_->rootObject();
			if (!root)
				return;
			QMetaObject::invokeMethod(root, "beginChannel", Q_ARG(QVariant, channel));
			for (const auto m : e["messages"].toArray())
				appendToQml(root, m.toObject());
			log("loaded #" + channel + " — " +
			    QString::number(e["messages"].toArray().size()) + " messages");
			return;
		}

		if (kind == "message") {
			const QString channel = e["channel"].toString();
			log("#" + channel + " " + e["author"].toString() + ": " +
			    e["body"].toString());

			// Only render what belongs to the channel being viewed. The message
			// is already stored daemon-side, so switching back will show it.
			if (channel != channel_) {
				markUnread(channel);
				return;
			}
			if (auto *root = quick_->rootObject())
				appendToQml(root, e);
			return;
		}

		log("unknown event: " + kind);
	}

	void appendToQml(QQuickItem *root, const QJsonObject &m) {
		QMetaObject::invokeMethod(
		    root, "appendMessage", Q_ARG(QVariant, m["author"].toString()),
		    Q_ARG(QVariant, m["colour"].toString()),
		    Q_ARG(QVariant, m["body"].toString()), Q_ARG(QVariant, m["time"].toString()),
		    Q_ARG(QVariant, m["mine"].toBool()), Q_ARG(QVariant, int(m["seq"].toInt())));
	}

	void markUnread(const QString &channel) {
		for (int i = 0; i < channels_->count(); ++i) {
			auto *item = channels_->item(i);
			if (item->text().mid(2).startsWith(channel)) {
				if (!item->text().endsWith(" •"))
					item->setText("# " + channel + " •");
				return;
			}
		}
	}

	void log(const QString &s) { log_->append(s); }

	QLocalSocket sock_;
	QByteArray buffer_;
	QQuickWidget *quick_ = nullptr;
	QListWidget *channels_ = nullptr;
	QListWidget *members_ = nullptr;
	QString channel_;
	QTextBrowser *log_ = nullptr;
	Q_OBJECT
};

#include "main.moc"

int main(int argc, char **argv) {
	QApplication app(argc, argv);
	Window w;
	w.show();

	if (qEnvironmentVariableIsSet("VEIL_AUTOQUIT")) {
		QTimer::singleShot(1500, [&w] { w.send("typed into the composer, stored by the daemon"); });
		QTimer::singleShot(3000, [&w] { w.selectChannelForDemo("protocol"); });
		QTimer::singleShot(5000, [&w] {
			w.grab().save("shot.png");
			QApplication::quit();
		});
	}
	return app.exec();
}
