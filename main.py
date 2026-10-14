# ============================================================
# NETWORK TRAFFIC ANALYZER
# Application Entry Point
# ============================================================

import sys

from PySide6.QtWidgets import QApplication

from frontend.main_window import MainWindow


def main():
    """
    Application entry point.
    """

    app = QApplication(sys.argv)

    # --------------------------------------------------------
    # Application information
    # --------------------------------------------------------

    app.setApplicationName(
        "Network Traffic Analyzer"
    )

    app.setApplicationDisplayName(
        "Network Traffic Analyzer"
    )

    app.setOrganizationName(
        "Network Defense Monitor"
    )

    # --------------------------------------------------------
    # Create main window
    # --------------------------------------------------------

    window = MainWindow()

    # --------------------------------------------------------
    # Show application
    # --------------------------------------------------------

    window.show()

    # --------------------------------------------------------
    # Start Qt event loop
    # --------------------------------------------------------

    sys.exit(
        app.exec()
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    main()