"""릴리즈 이미지용 백엔드 코드 보호 (Dockerfile 의 빌드 단계에서 실행).

결과물(out/)에는 .py 소스가 남지 않는다.
  1) CYTHON_PACKAGES 의 모듈  → C 로 변환 후 네이티브 확장(.so)으로 컴파일
  2) 나머지 app/ 모듈         → 바이트코드(.pyc)만 남기고 소스 제거
  3) migrations/              → 그대로 복사 (Alembic 이 .py 를 읽는다. 스키마 정의일 뿐이다)

기대 수준: 이미지가 유출됐을 때 소스가 그대로 읽히지 않게 하는 지연 수단이다.
.pyc 는 디컴파일 도구로 상당 부분 복원되므로, 보호 가치가 큰 로직은
CYTHON_PACKAGES 에 넣는다. 단, FastAPI 가 시그니처를 검사하는 코드(라우터,
Pydantic 모델, Depends 대상)는 Cython 으로 컴파일하면 동작이 달라질 수 있으니
동기 함수·평범한 클래스로 된 모듈만 넣는다.

사용:  python build_protect.py [출력 폴더=out]
"""
import compileall
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# 네이티브로 컴파일할 패키지 (ROOT 기준 경로). 필요하면 추가한다.
CYTHON_PACKAGES = ["app/security/core"]


def cythonize_packages(stage: Path) -> None:
    from Cython.Build import cythonize
    from setuptools import Extension, setup

    extensions = []
    for package in CYTHON_PACKAGES:
        for source in sorted((stage / package).glob("*.py")):
            if source.name == "__init__.py":
                continue
            module = ".".join(source.relative_to(stage).with_suffix("").parts)
            extensions.append(Extension(module, [str(source.relative_to(stage))]))
    if not extensions:
        return

    setup(
        script_args=["build_ext", "--inplace", "--build-temp", str(stage / "_build")],
        ext_modules=cythonize(
            extensions,
            language_level=3,
            # 소스 줄 정보와 docstring 을 결과물에 남기지 않는다.
            compiler_directives={"embedsignature": False, "emit_code_comments": False},
        ),
    )

    for package in CYTHON_PACKAGES:
        for source in (stage / package).glob("*.py"):
            if source.name == "__init__.py":
                continue
            source.unlink()
            source.with_suffix(".c").unlink(missing_ok=True)
    shutil.rmtree(stage / "_build", ignore_errors=True)
    shutil.rmtree(stage / "build", ignore_errors=True)  # build_ext 의 중간 산출물


def main() -> None:
    out = (ROOT / (sys.argv[1] if len(sys.argv) > 1 else "out")).resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    shutil.copytree(ROOT / "app", out / "app", ignore=ignore)
    shutil.copytree(ROOT / "migrations", out / "migrations", ignore=ignore)

    import os

    os.chdir(out)  # setuptools 는 현재 폴더 기준 상대 경로만 받는다
    cythonize_packages(out)

    # 나머지: 소스 옆에 .pyc 를 만들고(-b) .py 를 지운다. 주석·docstring·assert 제거(optimize=2).
    ok = compileall.compile_dir(str(out / "app"), legacy=True, optimize=2, quiet=1, ddir="app")
    if not ok:
        raise SystemExit("바이트코드 컴파일 실패")
    for source in (out / "app").rglob("*.py"):
        source.unlink()

    leftovers = [p for p in (out / "app").rglob("*") if p.suffix in {".py", ".c"}]
    if leftovers:
        raise SystemExit(f"소스가 남아 있습니다: {leftovers}")
    print(f"protected build -> {out}")


if __name__ == "__main__":
    main()
