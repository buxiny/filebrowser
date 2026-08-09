<template>
  <div class="totp-form">
    <h3>{{ t("settings.totpTitle") }}</h3>

    <!-- Disabled: offer to enable, or show the enable flow once enroll ran -->
    <div v-if="!user.totpEnabled">
      <!-- Enable flow: show QR + secret, wait for verification -->
      <template v-if="pending">
        <p class="small">{{ t("settings.totpScanHint") }}</p>
        <qrcode-vue
          v-if="enrollData"
          :value="enrollData.keyUrl"
          :size="180"
          level="M"
          class="totp-qr"
        ></qrcode-vue>
        <p class="small">
          {{ t("settings.totpManualEntry") }}
          <code class="totp-secret">{{ enrollData?.secret }}</code>
        </p>
        <p>
          <input
            class="input"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            maxlength="6"
            v-model="code"
            :placeholder="t('settings.totpCodePlaceholder')"
            @keyup.enter="verify"
          />
          <button
            class="button button--flat"
            type="button"
            :disabled="loading || code.length < 6"
            @click="verify"
          >
            {{ t("settings.totpConfirm") }}
          </button>
        </p>
        <p>
          <button
            class="button button--flat button--grey"
            type="button"
            :disabled="loading"
            @click="cancel"
          >
            {{ t("buttons.cancel") }}
          </button>
        </p>
      </template>

      <button
        v-else
        class="button button--flat"
        type="button"
        :disabled="loading"
        @click="enroll"
      >
        {{ t("settings.totpEnable") }}
      </button>
    </div>

    <!-- Enabled: show status + disable button -->
    <div v-else>
      <p class="small totp-enabled">{{ t("settings.totpEnabled") }}</p>
      <button
        class="button button--flat button--red"
        type="button"
        :disabled="loading"
        @click="disable"
      >
        {{ t("settings.totpDisable") }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { inject, ref } from "vue";
import { useI18n } from "vue-i18n";
import QrcodeVue from "qrcode.vue";
import { users as api } from "@/api";
import type { ITOTPEnrollResult } from "@/api/users";

const props = defineProps<{ user: IUser }>();
const emit = defineEmits<{ (e: "changed"): void }>();

const { t } = useI18n();
const $showError = inject<IToastError>("$showError")!;
const $showSuccess = inject<IToastSuccess>("$showSuccess")!;

const loading = ref<boolean>(false);
const pending = ref<boolean>(false);
const enrollData = ref<ITOTPEnrollResult | null>(null);
const code = ref<string>("");

const showError = (e: unknown) => {
  $showError(e instanceof Error ? e : new Error(String(e)));
};

const enroll = async () => {
  loading.value = true;
  try {
    enrollData.value = await api.totpEnroll(props.user.id);
    pending.value = true;
    code.value = "";
  } catch (e) {
    showError(e);
  } finally {
    loading.value = false;
  }
};

const verify = async () => {
  if (!enrollData.value || code.value.length < 6) {
    return;
  }
  loading.value = true;
  try {
    await api.totpVerify(props.user.id, enrollData.value.secret, code.value);
    pending.value = false;
    enrollData.value = null;
    code.value = "";
    $showSuccess(t("settings.totpEnabledSuccess"));
    emit("changed");
  } catch (e) {
    showError(e);
  } finally {
    loading.value = false;
  }
};

const disable = async () => {
  loading.value = true;
  try {
    await api.totpDisable(props.user.id);
    $showSuccess(t("settings.totpDisabledSuccess"));
    emit("changed");
  } catch (e) {
    showError(e);
  } finally {
    loading.value = false;
  }
};

const cancel = () => {
  pending.value = false;
  enrollData.value = null;
  code.value = "";
};
</script>

<style scoped>
.totp-form {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid rgba(127, 127, 127, 0.3);
}

.totp-form h3 {
  margin: 0 0 8px;
}

.totp-qr {
  margin: 10px 0;
}

.totp-secret {
  word-break: break-all;
  user-select: all;
}

.totp-enabled {
  color: var(--color-green, #2e7d32);
}
</style>
