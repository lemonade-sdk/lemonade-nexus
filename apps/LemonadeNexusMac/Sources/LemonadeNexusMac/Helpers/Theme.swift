import SwiftUI
import AppKit

// MARK: - Colors

extension Color {
    static let lemonYellow = Color(red: 1.0, green: 0.882, blue: 0.208)       // #FFE135
    static let lemonYellowDark = Color(red: 0.9, green: 0.78, blue: 0.1)
    static let lemonGreen = Color(red: 0.298, green: 0.686, blue: 0.314)      // #4CAF50
    static let nodeOrange = Color(red: 1.0, green: 0.42, blue: 0.0)           // #FF6B00
    static let surfaceLight = Color(NSColor.controlBackgroundColor)
    static let surfaceDark = Color(NSColor.windowBackgroundColor)
    static let textPrimary = Color(NSColor.labelColor)
    static let textSecondary = Color(NSColor.secondaryLabelColor)
    static let textTertiary = Color(NSColor.tertiaryLabelColor)
}

// MARK: - Card Modifier

struct CardModifier: ViewModifier {
    var padding: CGFloat = 16
    var cornerRadius: CGFloat = 12

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: cornerRadius))
            .shadow(color: Color.black.opacity(0.08), radius: 4, x: 0, y: 2)
    }
}

extension View {
    func cardStyle(padding: CGFloat = 16, cornerRadius: CGFloat = 12) -> some View {
        modifier(CardModifier(padding: padding, cornerRadius: cornerRadius))
    }
}

// MARK: - Status Dot

struct StatusDot: View {
    let isHealthy: Bool
    var size: CGFloat = 10

    var body: some View {
        Circle()
            .fill(isHealthy ? Color.green : Color.red)
            .frame(width: size, height: size)
            .shadow(color: (isHealthy ? Color.green : Color.red).opacity(0.5), radius: 3)
    }
}

// MARK: - Badge View

struct BadgeView: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption2)
            .fontWeight(.semibold)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.2))
            .foregroundColor(color)
            .clipShape(Capsule())
    }
}

// MARK: - Section Header

struct SectionHeaderView: View {
    let title: String
    let icon: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundColor(.lemonYellow)
                .font(.headline)
            Text(title)
                .font(.headline)
                .foregroundColor(.textPrimary)
            Spacer()
        }
    }
}

// MARK: - Loading Overlay

struct LoadingOverlay: View {
    let message: String

    var body: some View {
        ZStack {
            Color.black.opacity(0.2)
                .ignoresSafeArea()

            VStack(spacing: 16) {
                ProgressView()
                    .scaleEffect(1.5)
                    .tint(.lemonYellow)
                Text(message)
                    .font(.subheadline)
                    .foregroundColor(.textSecondary)
            }
            .padding(32)
            .background(.ultraThinMaterial)
            .clipShape(RoundedRectangle(cornerRadius: 16))
        }
    }
}

// MARK: - Lemon Button Style

struct LemonButtonStyle: ButtonStyle {
    var isProminent: Bool = true

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .padding(.horizontal, 20)
            .padding(.vertical, 10)
            .background(isProminent ? Color.lemonYellow : Color.clear)
            .foregroundColor(isProminent ? .black : .lemonYellow)
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(isProminent ? Color.clear : Color.lemonYellow, lineWidth: 1.5)
            )
            .scaleEffect(configuration.isPressed ? 0.97 : 1.0)
            .animation(.easeInOut(duration: 0.1), value: configuration.isPressed)
    }
}

// MARK: - Stat Card

struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    var color: Color = .lemonYellow

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(color)
                    .font(.title3)
                Spacer()
            }
            Text(value)
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .foregroundColor(.textPrimary)
            Text(title)
                .font(.caption)
                .foregroundColor(.textSecondary)
        }
        .cardStyle()
    }
}

// MARK: - Empty State View

struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: icon)
                .font(.system(size: 48))
                .foregroundColor(.textTertiary)
            Text(title)
                .font(.headline)
                .foregroundColor(.textSecondary)
            Text(message)
                .font(.subheadline)
                .foregroundColor(.textTertiary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}

// MARK: - Relative Time Formatter

func relativeTimeString(from dateString: String) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    var date = formatter.date(from: dateString)
    if date == nil {
        formatter.formatOptions = [.withInternetDateTime]
        date = formatter.date(from: dateString)
    }
    guard let parsedDate = date else { return dateString }

    let relFormatter = RelativeDateTimeFormatter()
    relFormatter.unitsStyle = .short
    return relFormatter.localizedString(for: parsedDate, relativeTo: Date())
}

func formatDate(_ dateString: String) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    var date = formatter.date(from: dateString)
    if date == nil {
        formatter.formatOptions = [.withInternetDateTime]
        date = formatter.date(from: dateString)
    }
    guard let parsedDate = date else { return dateString }

    let displayFormatter = DateFormatter()
    displayFormatter.dateStyle = .medium
    displayFormatter.timeStyle = .short
    return displayFormatter.string(from: parsedDate)
}

// MARK: - Epoch Timestamp Helpers

func relativeTimeString(fromEpoch epoch: UInt64?) -> String {
    guard let epoch = epoch, epoch > 0 else { return "Unknown" }
    let date = Date(timeIntervalSince1970: TimeInterval(epoch))
    let relFormatter = RelativeDateTimeFormatter()
    relFormatter.unitsStyle = .short
    return relFormatter.localizedString(for: date, relativeTo: Date())
}

func formatDate(fromEpoch epoch: UInt64?) -> String {
    guard let epoch = epoch, epoch > 0 else { return "Unknown" }
    let date = Date(timeIntervalSince1970: TimeInterval(epoch))
    let displayFormatter = DateFormatter()
    displayFormatter.dateStyle = .medium
    displayFormatter.timeStyle = .short
    return displayFormatter.string(from: date)
}
