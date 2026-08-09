<template>
  <div id="login" :class="{ recaptcha: recaptcha }">
    <form @submit="submit">
      <img :src="logoURL" alt="File Browser" />
      <h1>{{ name }}</h1>
      <p v-if="reason != null" class="logout-message">
        {{ t(`login.logout_reasons.${reason}`) }}
      </p>
      <div v-if="error !== ''" class="wrong">{{ error }}</div>

      <input
        autofocus
        class="input input--block"
        type="text"
        autocapitalize="off"
        v-model="username"
        :placeholder="t('login.username')"
        :disabled="totpStep"
      />
      <input
        class="input input--block"
        type="password"
        v-model="password"
        :placeholder="t('login.password')"
        :disabled="totpStep"
      />
      <input
        class="input input--block"
        v-if="createMode"
        type="password"
        v-model="passwordConfirm"
        :placeholder="t('login.passwordConfirm')"
      />

      <div v-if="totpStep" class="totp">
        <p class="totp-hint">{{ t("login.enterTotp") }}</p>
        <input
          class="input input--block"
          type="text"
          inputmode="numeric"
          autocomplete="one-time-code"
          maxlength="6"
          v-model="totpCode"
          :placeholder="t('login.totp')"
          autofocus
        />
      </div>

      <div v-if="recaptcha" id="recaptcha"></div>
      <input
        class="button button--block"
        type="submit"
        :value="
          totpStep
            ? t('login.submitTotp')
            : createMode
              ? t('login.signup')
              : t('login.submit')
        "
      />

      <p @click="toggleMode" v-if="signup && !totpStep">
        {{ createMode ? t("login.loginInstead") : t("login.createAnAccount") }}
      </p>
    </form>
  </div>
</template>

<script setup lang="ts">
import { StatusError } from "@/api/utils";
import * as auth from "@/utils/auth";
import {
  name,
  logoURL,
  recaptcha,
  recaptchaKey,
  signup,
} from "@/utils/constants";
import { inject, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { useRoute, useRouter } from "vue-router";

// Define refs
const createMode = ref<boolean>(false);
const error = ref<string>("");
const username = ref<string>("");
const password = ref<string>("");
const passwordConfirm = ref<string>("");
const totpStep = ref<boolean>(false);
const totpCode = ref<string>("");

const route = useRoute();
const router = useRouter();
const { t } = useI18n({});
// Define functions
const toggleMode = () => (createMode.value = !createMode.value);

const $showError = inject<IToastError>("$showError")!;

const reason = route.query["logout-reason"] ?? null;

const submit = async (event: Event) => {
  event.preventDefault();
  event.stopPropagation();

  const redirect = (route.query.redirect || "/files/") as string;

  let captcha = "";
  if (recaptcha) {
    captcha = window.grecaptcha.getResponse();

    if (captcha === "") {
      error.value = t("login.wrongCredentials");
      return;
    }
  }

  if (createMode.value) {
    if (password.value !== passwordConfirm.value) {
      error.value = t("login.passwordsDontMatch");
      return;
    }
  }

  try {
    if (createMode.value) {
      await auth.signup(username.value, password.value);
    }

    await auth.login(
      username.value,
      password.value,
      captcha,
      totpStep.value ? totpCode.value : ""
    );
    router.push({ path: redirect });
  } catch (e: any) {
    // console.error(e);
    if (e instanceof StatusError) {
      if (e.status === 428) {
        // Valid credentials but a TOTP code is required: move to step 2.
        totpStep.value = true;
        error.value = "";
        return;
      } else if (e.status === 409) {
        error.value = t("login.usernameTaken");
      } else if (e.status === 403) {
        // Wrong password or wrong TOTP code; reset the step so a wrong code
        // does not silently keep the user on the TOTP screen with stale data.
        if (totpStep.value) {
          totpStep.value = false;
          totpCode.value = "";
        }
        error.value = t("login.wrongCredentials");
      } else if (e.status === 400) {
        const match = e.message.match(/minimum length is (\d+)/);
        if (match) {
          error.value = t("login.passwordTooShort", { min: match[1] });
        } else {
          error.value = e.message;
        }
      } else {
        $showError(e);
      }
    }
  }
};

// Run hooks
onMounted(() => {
  if (!recaptcha) return;

  window.grecaptcha.ready(function () {
    window.grecaptcha.render("recaptcha", {
      sitekey: recaptchaKey,
    });
  });
});
</script>

<style scoped>
.totp {
  margin-bottom: 10px;
}

.totp-hint {
  margin: 0 0 5px;
  font-size: 0.9em;
  opacity: 0.8;
}
</style>
