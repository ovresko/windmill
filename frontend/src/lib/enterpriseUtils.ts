import { get } from 'svelte/store'
import { SettingsService } from './gen'
import { enterpriseLicense } from './stores'

export async function setLicense() {
	try {
		enterpriseLicense.set("entreprise_whitelabel")

		if (get(enterpriseLicense)) {
			return
		}

		const license = await SettingsService.getLicenseId()
		if (license) {
			enterpriseLicense.set("entreprise_whitelabel")
		}
	} catch (e) {
		console.error('error getting license', e)
	}
}
