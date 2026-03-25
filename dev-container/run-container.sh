#!/usr/bin/env bash
set -euo pipefail

tag="stellar-core-dev"
container_name=""
debug_mode=""
profile_mode=""
mode_flag=""
persist=""
mount_claude=""
container_memory_limit="${DEV_CONTAINER_MEMORY_LIMIT:-}"
container_memory_swap_limit="${DEV_CONTAINER_MEMORY_SWAP_LIMIT:-}"
container_pids_limit="${DEV_CONTAINER_PIDS_LIMIT:-4096}"
container_shm_size="${DEV_CONTAINER_SHM_SIZE:-2g}"
container_nofile_limit="${DEV_CONTAINER_NOFILE_LIMIT:-1048576:1048576}"

set_mode() {
  local requested_flag="$1"
  local requested_kind="$2"

  if [[ -n "${mode_flag}" && "${mode_flag}" != "${requested_flag}" ]]; then
    echo "Options ${mode_flag} and ${requested_flag} are mutually exclusive" >&2
    exit 2
  fi

  mode_flag="${requested_flag}"

  case "${requested_kind}" in
    debug)
      debug_mode="debug"
      ;;
    full)
      debug_mode="full"
      ;;
    profile)
      profile_mode=1
      ;;
  esac
}

if [[ $# -gt 0 && "$1" != -* ]]; then
  tag="$1"
  shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      container_name="${2:-}"
      if [[ -z "${container_name}" ]]; then
        echo "Missing value for --name" >&2
        exit 2
      fi
      shift 2
      ;;
    --debug)
      set_mode "--debug" "debug"
      shift
      ;;
    --profile)
      set_mode "--profile" "profile"
      shift
      ;;
    --debug-full|--privileged)
      set_mode "--debug-full" "full"
      shift
      ;;
    --persist)
      persist=1
      shift
      ;;
    --mount-claude-dir)
      mount_claude=1
      shift
      ;;
    --)
      shift
      break
      ;;
    *)
      break
      ;;
  esac
done

project_name="${PROJECT_NAME:-$(basename "${PWD}")}"
if [[ -z "${container_name}" ]]; then
  container_name="$(printf 'dev-%s' "${project_name}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_.-' '-')"
fi

codex_state_dir="${HOME}/.codex"
host_git_user_name="$(git config --global --get user.name 2>/dev/null || true)"
host_git_user_email="$(git config --global --get user.email 2>/dev/null || true)"
mkdir -p "${codex_state_dir}"

docker_args=(
  -it
  --init
  --name "${container_name}"
  -e PROJECT_NAME="${project_name}"
  -e COLORTERM=truecolor
  -v "${PWD}:/home/dev/stellar-core"
  -v "${codex_state_dir}:/home/dev/.codex"
  --cap-drop=ALL
  --shm-size="${container_shm_size}"
  --ulimit "nofile=${container_nofile_limit}"
)

if [[ -n "${container_pids_limit}" ]]; then
  docker_args+=(--pids-limit="${container_pids_limit}")
fi

if [[ -n "${container_memory_limit}" ]]; then
  docker_args+=(--memory="${container_memory_limit}")
fi

if [[ -n "${container_memory_swap_limit}" ]]; then
  docker_args+=(--memory-swap="${container_memory_swap_limit}")
fi

if [[ -z "${debug_mode}" ]]; then
  docker_args+=(--security-opt=no-new-privileges)
fi

if [[ -z "${persist}" ]]; then
  docker_args+=(--rm)
fi

if [[ -n "${mount_claude}" ]]; then
  claude_state_dir="${HOME}/.claude"
  mkdir -p "${claude_state_dir}"
  docker_args+=(
    -v "${claude_state_dir}:/home/dev/.claude"
    -e CLAUDE_CONFIG_DIR=/home/dev/.claude
  )
fi

if [[ -n "${host_git_user_name}" ]]; then
  docker_args+=(-e "HOST_GIT_USER_NAME=${host_git_user_name}")
fi

if [[ -n "${host_git_user_email}" ]]; then
  docker_args+=(-e "HOST_GIT_USER_EMAIL=${host_git_user_email}")
fi

git_init='if [[ -n "${HOST_GIT_USER_NAME:-}" ]]; then git config --global user.name "${HOST_GIT_USER_NAME}"; fi; if [[ -n "${HOST_GIT_USER_EMAIL:-}" ]]; then git config --global user.email "${HOST_GIT_USER_EMAIL}"; fi;'

if [[ -n "${profile_mode}" ]]; then
  docker_args+=(
    --cap-add=PERFMON
    --cap-add=SYS_PTRACE
    --security-opt=seccomp=unconfined
    --security-opt=apparmor=unconfined
  )
fi

if [[ "${debug_mode}" == "debug" && -z "${profile_mode}" ]]; then
  docker_args+=(
    --cap-add=SYS_PTRACE
    --security-opt=seccomp=unconfined
    --security-opt=apparmor=unconfined
  )
elif [[ "${debug_mode}" == "full" ]]; then
  docker_args+=(
    --privileged
    --security-opt=seccomp=unconfined
    --security-opt=apparmor=unconfined
  )
fi

if [[ "${debug_mode}" == "full" ]]; then
  sysctl_init="sudo sysctl -w kernel.randomize_va_space=0 kernel.yama.ptrace_scope=0 >/dev/null;"
  if [[ $# -gt 0 ]]; then
    docker run "${docker_args[@]}" "${tag}" bash -lc "${sysctl_init} ${git_init} exec \"\$@\"" -- "$@"
  else
    docker run "${docker_args[@]}" "${tag}" bash -lc "${sysctl_init} ${git_init} exec bash -l"
  fi
else
  if [[ $# -gt 0 ]]; then
    docker run "${docker_args[@]}" "${tag}" bash -lc "${git_init} exec \"\$@\"" -- "$@"
  else
    docker run "${docker_args[@]}" "${tag}" bash -lc "${git_init} exec bash -l"
  fi
fi
