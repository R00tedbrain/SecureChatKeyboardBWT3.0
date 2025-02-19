###################################################
## Reglas de Keep para tu IME y vistas personalizadas
###################################################
-keep public class * extends android.inputmethodservice.InputMethodService {
    public <init>(...);
}
-keep class com.bwt.securechats.inputmethod.R { *; }
-keep class com.bwt.securechats.inputmethod.R$* { *; }
-keep class com.bwt.securechats.inputmethod.BuildConfig { *; }
# (Agrega aquí otras reglas para tus vistas infladas desde XML)

###################################################
## Jackson
###################################################
-keep class com.fasterxml.jackson.** { *; }
-dontwarn com.fasterxml.jackson.**

###################################################
## libsignal-android
###################################################
-dontwarn org.whispersystems.**
-keep class org.whispersystems.** { *; }

###################################################
## Protobuf (javalite)
###################################################
-keep class com.google.protobuf.GeneratedMessageLite { *; }
-keep class com.google.protobuf.GeneratedMessageLite$Builder { *; }
-keepclassmembers class * extends com.google.protobuf.GeneratedMessageLite {
    public static com.google.protobuf.Parser parser();
}
-keep class com.google.protobuf.MessageLite { *; }
-keep class com.google.protobuf.ExtensionLite { *; }
-dontwarn com.google.protobuf.**

###################################################
## Atributos y anotaciones
###################################################
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes EnclosingMethod
-keepattributes InnerClasses
