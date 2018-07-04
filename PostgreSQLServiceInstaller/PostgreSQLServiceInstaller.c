#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

#define ACTION_INSTALL 0
#define ACTION_UNINSTALL 1

int main(int argc, char **argv) {

	char *key = NULL;
	char *value = NULL;

	int int_action = 0;
	char *str_target_dir = NULL;

	if (argc < 2) {
		printf("Not enough arguments\n");
		getchar();
		return 1;
	} else {
		if (*argv[1] == '/') {
			key = argv[1] + 1;
			value = strchr(key, ':');
			if (value != NULL) *value++ = 0;

			printf("key: %s\n", key);

			if (strncmp(key, "I", 2) == 0) {
				printf("ACTION_INSTALL\n");
				int_action = ACTION_INSTALL;
				str_target_dir = value;
			}

			if (strncmp(key, "U", 2) == 0) {
				printf("ACTION_UNINSTALL\n");
				int_action = ACTION_UNINSTALL;
				str_target_dir = value;
			}


		} else {
			printf("Invalid argument: %s\n", argv[1]);
			getchar();
			return 1;
		}
	}

	char *str_log_part = "\\log\\PostgreSQLServiceInstaller.log";
	char *str_log = NULL;

	str_log = calloc(strlen(str_target_dir) + strlen(str_log_part), 1);
	if (str_log == NULL) {
		printf("calloc failed: %d\n", GetLastError());
		getchar();
		return 1;
	}
	memcpy(str_log, str_target_dir, strlen(str_target_dir));
	memcpy(str_log + strlen(str_target_dir) - 1, str_log_part, strlen(str_log_part));

	FILE *log = fopen(str_log, "a+");
	if (log == NULL) {
		printf("Couldn't open file %s: %s (errno %d)\n", str_log, strerror(errno), errno);
		getchar();
		return 1;
	}

	SC_HANDLE sc_manager = OpenSCManagerA(NULL, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CREATE_SERVICE);
	SC_HANDLE sc_service = NULL;

	if (sc_manager == NULL) {
		fprintf(log, "OpenSCManagerA failed: %d\n", GetLastError());
		fclose(log);
		getchar();
		return 1;
	}

	if (int_action == ACTION_INSTALL) {
		char *str_binpath_part = "\\postgresql\\bin\\PostgreSQLService.exe";
		char *str_binpath = NULL;

		str_binpath = calloc(strlen(str_target_dir) + strlen(str_binpath_part), 1);
		if (str_binpath == NULL) {
			fprintf(log, "calloc failed: %d\n", GetLastError());
			fclose(log);
			return 1;
		}
		memcpy(str_binpath, str_target_dir, strlen(str_target_dir));
		memcpy(str_binpath + strlen(str_target_dir) - 1, str_binpath_part, strlen(str_binpath_part));

		fprintf(log, "str_binpath: %s\n", str_binpath);

		fprintf(log, "ACTION_INSTALL\n");
		sc_service = CreateServiceA(
			sc_manager,
			"Production Line PostgreSQL",
			"Production Line PostgreSQL",
			SERVICE_ALL_ACCESS,
			SERVICE_WIN32_OWN_PROCESS,
			SERVICE_AUTO_START,
			SERVICE_ERROR_NORMAL,
			str_binpath,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		);

		free(str_binpath);

		if (sc_service == NULL) {
			fprintf(log, "CreateServiceA failed: %d\n", GetLastError());
			fclose(log);
			getchar();
			return 1;
		}

		if (StartServiceA(sc_service, 0, NULL) == FALSE) {
			fprintf(log, "StartService failed: %d\n", GetLastError());
			fclose(log);
			getchar();
			return 1;
		}

		if (CloseServiceHandle(sc_service) == FALSE) {
			fprintf(log, "CloseServiceHandle failed: %d\n", GetLastError());
			fclose(log);
			getchar();
			return 1;
		}
	} else {
		fprintf(log, "ACTION_UNINSTALL\n");
		SERVICE_STATUS_PROCESS ssp;
		sc_service = OpenServiceA(sc_manager, "Production Line PostgreSQL", SERVICE_ALL_ACCESS);

		if (sc_service == NULL) {
			fprintf(log, "OpenServiceA failed: %d\n", GetLastError());
			fclose(log);
			// at this point, it doesn't matter
			return 0;
		}

		// 1062: The service was not started
		// 109: The pipe has ended
		BOOL bol_ret = ControlService(sc_service, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
		DWORD int_err = GetLastError();
		if (bol_ret != 0 && (int_err != 0 && int_err != 1062 && int_err != 109)) {
			fprintf(log, "ControlService failed: %d\n", int_err);
			fclose(log);
			getchar();
			return 1;
		}

		if (DeleteService(sc_service) == FALSE) {
			fprintf(log, "DeleteService failed: %d\n", GetLastError());
			fclose(log);
			getchar();
			return 1;
		}

		if (CloseServiceHandle(sc_service) == FALSE) {
			fprintf(log, "CloseServiceHandle failed: %d\n", GetLastError());
			fclose(log);
			getchar();
			return 1;
		}
	}

	fprintf(log, "Complete and Utter Success!\n");
	fclose(log);
	return 0;
}