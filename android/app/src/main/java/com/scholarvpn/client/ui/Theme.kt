package com.scholarvpn.client.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

/**
 * 品牌主题：靛紫配色（明/暗跟随系统），全局大圆角。
 * 不启用 Material You 动态取色——VPN 应用保持品牌一致性优先。
 */

private val LightColors = lightColorScheme(
    primary = Color(0xFF4B54C8),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFDFE1FF),
    onPrimaryContainer = Color(0xFF000F66),
    secondary = Color(0xFF5B5D72),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFE0E1F9),
    onSecondaryContainer = Color(0xFF181B2C),
    tertiary = Color(0xFF00696D),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFF9CF1F1),
    onTertiaryContainer = Color(0xFF002021),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    background = Color(0xFFFBF8FF),
    onBackground = Color(0xFF1A1B21),
    surface = Color(0xFFFBF8FF),
    onSurface = Color(0xFF1A1B21),
    surfaceVariant = Color(0xFFE3E1EC),
    onSurfaceVariant = Color(0xFF46464F),
    outline = Color(0xFF767680),
    outlineVariant = Color(0xFFC7C5D0),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFBCC3FF),
    onPrimary = Color(0xFF1723A0),
    primaryContainer = Color(0xFF333DB4),
    onPrimaryContainer = Color(0xFFDFE1FF),
    secondary = Color(0xFFC4C5DD),
    onSecondary = Color(0xFF2D2F42),
    secondaryContainer = Color(0xFF43455A),
    onSecondaryContainer = Color(0xFFE0E1F9),
    tertiary = Color(0xFF80D4D4),
    onTertiary = Color(0xFF003738),
    tertiaryContainer = Color(0xFF004F50),
    onTertiaryContainer = Color(0xFF9CF1F1),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF111318),
    onBackground = Color(0xFFE3E2E8),
    surface = Color(0xFF111318),
    onSurface = Color(0xFFE3E2E8),
    surfaceVariant = Color(0xFF46464F),
    onSurfaceVariant = Color(0xFFC7C5D0),
    outline = Color(0xFF90909A),
    outlineVariant = Color(0xFF46464F),
)

private val AppShapes = androidx.compose.material3.Shapes(
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(18.dp),
    large = RoundedCornerShape(26.dp),
)

@Composable
fun ScholarVpnTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        shapes = AppShapes,
        content = content,
    )
}
