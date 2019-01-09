from setuptools import setup

setup(
    name='remotepspy',
    version='0.1.0',
    packages=['remotepspy'],
    classifiers=[
        'Programming Language :: Python :: 3.7',
        'License :: OSI Approved :: BSD License',
        'Operating System :: Microsoft :: Windows',
        'Development Status :: 4 - Beta',
        'Natural Language :: English',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: System :: Logging'
    ],
    keywords=['powershell', 'PowerShell', 'PSRP'],
    url='https://github.com/countercept/RemotePSpy',
    author='Matt Hillman',
    author_email='matt.hillman@countercept.com',
    description='Monitor and log remote PowerShell sessions.',
    long_description='RemotePSpy provides live monitoring of remote PowerShell sessions, which is particularly useful '
                     'for older (pre-5.0) versions of PowerShell which do not have comprehensive logging facilities '
                     'built in.',
    python_requires='>=3.7',
    install_requires=['psutil==5.4.8', 'pywintrace==0.1.1'],
    entry_points={
        'console_scripts': [
            'RemotePSpy = remotepspy.__main__:run_winrm_etw',
            'RemotePSpy_powershell_prov = remotepspy.__main__:run_powershell_etw'
        ]
    },
    package_data={'remotepspy': ['libwim_bin/32/*.dll', 'libwim_bin/64/*.dll']}
)
